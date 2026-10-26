"""
SchoolWise AI – Cố vấn Nội quy & Thi đua Học đường
Trường PTDTNT THCS & THPT Phước Sơn.
Full-stack Flask Application with RBAC, RAG Engine, Document Management, and Audit Logging.
"""
import os
import sys
import uuid
from functools import wraps
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

from database import init_db, get_db, verify_user, log_audit, get_user_by_id
from document_manager import index_file, toggle_document_status, delete_document, seed_official_documents
from rag_engine import ask_schoolwise, classify_topic

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "schoolwise-phuocson-secret-key-2026-2027-thcs-thpt")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB max upload
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database and seed official school docs on startup
init_db()
seed_official_documents()

# ================== RBAC DECORATORS ==================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Vui lòng đăng nhập để thực hiện thao tác này.", "code": "UNAUTHORIZED"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Yêu cầu đăng nhập tài khoản Quản trị viên (ADMIN).", "code": "UNAUTHORIZED"}), 401
        if session.get("role") != "admin":
            # Security Violation Log
            log_audit(
                session.get("username", "unknown"),
                "SECURITY_VIOLATION",
                target=request.path,
                details="USER tried to access ADMIN API.",
                ip_address=request.remote_addr,
                user_id=session.get("user_id")
            )
            return jsonify({"error": "Bạn không có quyền quản trị viên (ADMIN). Thao tác bị từ chối.", "code": "FORBIDDEN"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ================== AUTHENTICATION APIS ==================

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu."}), 400

    user = verify_user(username, password)
    if not user:
        return jsonify({"success": False, "message": "Tên đăng nhập hoặc mật khẩu không chính xác."}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]

    log_audit(user["username"], "LOGIN", details=f"Logged in as {user['role']}", ip_address=request.remote_addr, user_id=user["id"])

    return jsonify({
        "success": True,
        "message": f"Đăng nhập thành công! Chào mừng {user['full_name']}.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    username = session.get("username", "guest")
    user_id = session.get("user_id")
    log_audit(username, "LOGOUT", ip_address=request.remote_addr, user_id=user_id)
    session.clear()
    return jsonify({"success": True, "message": "Đã đăng xuất thành công."})

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    if "user_id" in session:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "full_name": session.get("full_name"),
                "role": session.get("role")
            }
        })
    return jsonify({
        "authenticated": False,
        "user": {
            "id": None,
            "username": "guest",
            "full_name": "Khách tham quan",
            "role": "guest"
        }
    })

# ================== CHATBOT RAG APIS ==================

@app.route("/api/ask", methods=["POST"])
def api_ask():
    data = request.get_json() or {}
    question = data.get("question", "").strip()
    session_id = data.get("session_id") or session.get("chat_session_id") or str(uuid.uuid4())
    session["chat_session_id"] = session_id
    user_id = session.get("user_id")

    if not question:
        return jsonify({"answer": "Vui lòng nhập câu hỏi nội quy.", "sources": [], "found": False}), 400

    # Execute RAG
    result = ask_schoolwise(question)

    # Save to chat history & analytics
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO chat_messages (session_id, user_id, sender, content, sources_json, created_at)
            VALUES (?, ?, 'user', ?, '', ?)
        """, (session_id, user_id, question, datetime.now().isoformat()))

        import json
        sources_str = json.dumps(result.get("sources", []), ensure_ascii=False)
        cursor.execute("""
            INSERT INTO chat_messages (session_id, user_id, sender, content, sources_json, created_at)
            VALUES (?, ?, 'assistant', ?, ?, ?)
        """, (session_id, user_id, result["answer"], sources_str, datetime.now().isoformat()))
        bot_msg_id = cursor.lastrowid

        # Save to analytics
        cursor.execute("""
            INSERT INTO question_analytics (question, topic, found, user_id, response_time_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (question, result.get("topic", "Khác"), 1 if result.get("found") else 0, user_id, result.get("response_time_ms", 0), datetime.now().isoformat()))

        conn.commit()

    return jsonify({
        "id": bot_msg_id,
        "answer": result["answer"],
        "sources": result.get("sources", []),
        "topic": result.get("topic", "Khác"),
        "found": result.get("found", True),
        "response_time_ms": result.get("response_time_ms", 0),
        "session_id": session_id
    })

@app.route("/api/history", methods=["GET"])
def api_history():
    session_id = request.args.get("session_id") or session.get("chat_session_id")
    if not session_id:
        return jsonify({"messages": []})

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, sender, content, sources_json, feedback, created_at
            FROM chat_messages
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,)).fetchall()

        messages = []
        import json
        for r in rows:
            srcs = []
            if r["sources_json"]:
                try:
                    srcs = json.loads(r["sources_json"])
                except Exception:
                    pass
            messages.append({
                "id": r["id"],
                "sender": r["sender"],
                "content": r["content"],
                "sources": srcs,
                "feedback": r["feedback"],
                "created_at": r["created_at"]
            })

    return jsonify({"messages": messages})

@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    session_id = request.args.get("session_id") or session.get("chat_session_id")
    if session_id:
        with get_db() as conn:
            conn.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
            conn.commit()
    # Reset session id
    session["chat_session_id"] = str(uuid.uuid4())
    return jsonify({"success": True, "message": "Đã xóa sạch lịch sử hội thoại."})

@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    data = request.get_json() or {}
    message_id = data.get("message_id")
    rating = data.get("rating", 0)  # 1 for positive, -1 for negative
    comment = data.get("comment", "").strip()

    if not message_id:
        return jsonify({"error": "Thiếu message_id"}), 400

    with get_db() as conn:
        conn.execute("""
            UPDATE chat_messages 
            SET feedback = ?, feedback_comment = ? 
            WHERE id = ?
        """, (rating, comment, message_id))
        conn.commit()

    return jsonify({"success": True, "message": "Cảm ơn bạn đã gửi phản hồi!"})

@app.route("/api/documents/handbook", methods=["GET"])
def api_handbook():
    """Provides categorized quick references from official school documents."""
    return jsonify({
        "school": "Trường PTDTNT THCS & THPT Phước Sơn",
        "school_year": "2026 - 2027",
        "categories": [
            {
                "id": "thoigian",
                "title": "⏰ Thời gian biểu 24/7",
                "items": [
                    {"time": "05:10 - 05:30", "activity": "Thức dậy, tập thể dục buổi sáng theo hiệu lệnh kẻng trực tuần."},
                    {"time": "06:00 - 06:40", "activity": "Nhà ăn mở cửa phát điểm tâm sáng cho học sinh."},
                    {"time": "06:45", "activity": "Vào lớp chính khóa buổi sáng (quá 6h45 tính đi muộn - trừ 1 điểm/lần)."},
                    {"time": "11:30 - 12:30", "activity": "Ăn trưa tại nhà ăn tập thể."},
                    {"time": "11:45 - 13:30", "activity": "Nghỉ trưa tại phòng ký túc xá, giữ trật tự chung."},
                    {"time": "13:50", "activity": "Vào lớp học buổi chiều (quá 13h50 tính đi muộn - trừ 1 điểm/lần)."},
                    {"time": "18:00 - 19:00", "activity": "Ăn tối tại nhà bếp tập thể."},
                    {"time": "19:00 - 21:00", "activity": "Giờ tự học bắt buộc tại lớp/thư viện (quá 19h00 tính đi muộn)."},
                    {"time": "22:00", "activity": "Giờ giới nghiêm: Tắt đèn, đi ngủ, cấm ra khỏi phòng ký túc xá."}
                ]
            },
            {
                "id": "dongphuc",
                "title": "👔 Quy định Đồng phục & Tác phong",
                "items": [
                    {"item": "Thứ Hai (Chào cờ)", "desc": "Mặc đồng phục theo quy định hoặc trang phục truyền thống dân tộc bản địa."},
                    {"item": "Ngày học thường", "desc": "Áo trắng đồng phục hoặc áo đoàn thanh niên, đeo phù hiệu trường, quần tây xanh/đen."},
                    {"item": "Giày dép", "desc": "Mang dép có quai hậu hoặc giày bata/thể thao. Không đi dép lê lên lớp học."},
                    {"item": "Tác phong", "desc": "Không nhuộm tóc màu sáng, không cạo trọc hay để tóc quá dài (nam), không sơn móng tay, không trang điểm đậm."}
                ]
            },
            {
                "id": "noitru",
                "title": "🏢 Quy định Ký túc xá & Nhà ăn",
                "items": [
                    {"item": "Sắp xếp nội vụ", "desc": "Chăn màn phải gấp vuông vức theo kiểu 'bánh chưng', mùng mắc đúng quy cách sau khi ngủ dậy."},
                    {"item": "An toàn cháy nổ", "desc": "Nghiêm cấm nấu nướng trong phòng ở; cấm dùng bếp gas mini, ấm siêu tốc hoặc các chất dễ cháy."},
                    {"item": "Tiếp khách", "desc": "Không cho người lạ hoặc bạn khác giới vào phòng ở; tiếp đón người thân tại phòng khách nhà trường."},
                    {"item": "Ra khỏi cổng trường", "desc": "Bắt buộc phải có Giấy phép / Thẻ phép có chữ ký của Quản sinh/GV trực và nộp thẻ HS cho bảo vệ."}
                ]
            },
            {
                "id": "thangdiem",
                "title": "📊 Biểu điểm Thi đua & Trừ điểm",
                "items": [
                    {"item": "Đi học muộn (sáng quá 6h45, chiều 13h50, tối 19h00)", "desc": "Trừ 1 điểm / học sinh / lần vi phạm."},
                    {"item": "Bỏ tiết học không phép", "desc": "Trừ 2 điểm / học sinh / tiết."},
                    {"item": "Sai tác phong / không mang phù hiệu / đi dép lê", "desc": "Trừ 1 điểm / học sinh / lần vi phạm."},
                    {"item": "Phòng ở KTX bẩn / chăn màn không gấp", "desc": "Trừ 2 điểm / phòng / buổi kiểm tra."},
                    {"item": "Sử dụng điện thoại sai quy định trong giờ học", "desc": "Tạm thu điện thoại và trừ 2 điểm thi đua."}
                ]
            }
        ]
    })

# ================== ADMIN MANAGEMENT APIS (RBAC PROTECTED) ==================

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    """Returns administrative metrics and dashboard numbers."""
    today_str = datetime.now().date().isoformat()
    with get_db() as conn:
        # Documents count
        total_docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        indexed_docs = conn.execute("SELECT COUNT(*) FROM documents WHERE status = 'indexed'").fetchone()[0]
        error_docs = conn.execute("SELECT COUNT(*) FROM documents WHERE status = 'error'").fetchone()[0]
        disabled_docs = conn.execute("SELECT COUNT(*) FROM documents WHERE status = 'disabled'").fetchone()[0]
        total_chunks = conn.execute("SELECT COUNT(*) FROM document_chunks").fetchone()[0]

        # Analytics count
        total_queries = conn.execute("SELECT COUNT(*) FROM question_analytics").fetchone()[0]
        today_queries = conn.execute("SELECT COUNT(*) FROM question_analytics WHERE date(created_at) = date(?)", (today_str,)).fetchone()[0]
        not_found_queries = conn.execute("SELECT COUNT(*) FROM question_analytics WHERE found = 0").fetchone()[0]

        # Top queried topics
        topics_rows = conn.execute("""
            SELECT topic, COUNT(*) as cnt
            FROM question_analytics
            GROUP BY topic
            ORDER BY cnt DESC
        """).fetchall()

        # Questions by day (last 7 days)
        by_day_rows = conn.execute("""
            SELECT date(created_at) as day, COUNT(*) as cnt
            FROM question_analytics
            GROUP BY date(created_at)
            ORDER BY day DESC
            LIMIT 7
        """).fetchall()

        # Recent unanswered questions
        unanswered_rows = conn.execute("""
            SELECT id, question, topic, created_at
            FROM question_analytics
            WHERE found = 0
            ORDER BY id DESC
            LIMIT 15
        """).fetchall()

        # Feedback stats
        positive_fb = conn.execute("SELECT COUNT(*) FROM chat_messages WHERE feedback = 1").fetchone()[0]
        negative_fb = conn.execute("SELECT COUNT(*) FROM chat_messages WHERE feedback = -1").fetchone()[0]

    return jsonify({
        "documents": {
            "total": total_docs,
            "indexed": indexed_docs,
            "error": error_docs,
            "disabled": disabled_docs,
            "total_chunks": total_chunks
        },
        "queries": {
            "total": total_queries,
            "today": today_queries,
            "not_found": not_found_queries
        },
        "topics": [{"topic": r["topic"], "count": r["cnt"]} for r in topics_rows],
        "by_day": [{"day": r["day"], "count": r["cnt"]} for r in reversed(by_day_rows)],
        "unanswered": [{"id": r["id"], "question": r["question"], "topic": r["topic"], "created_at": r["created_at"]} for r in unanswered_rows],
        "feedback": {
            "positive": positive_fb,
            "negative": negative_fb,
            "satisfaction_rate": round(positive_fb / (positive_fb + negative_fb) * 100, 1) if (positive_fb + negative_fb) > 0 else 100
        }
    })

@app.route("/api/admin/documents", methods=["GET"])
@admin_required
def admin_get_documents():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, filename, original_name, file_type, file_size, doc_title, school_year, total_pages, total_chunks, status, is_active, uploaded_by, uploaded_at, updated_at, summary
            FROM documents
            ORDER BY id DESC
        """).fetchall()
        docs = [dict(r) for r in rows]
    return jsonify({"documents": docs})

@app.route("/api/admin/documents/upload", methods=["POST"])
@admin_required
def admin_upload_document():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "Chưa chọn file tải lên."}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"success": False, "message": "Tên file không hợp lệ."}), 400

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".pdf", ".docx", ".doc"):
        return jsonify({"success": False, "message": f"Chỉ hỗ trợ file .pdf, .docx, .doc. File '{ext}' không được chấp nhận."}), 400

    title = request.form.get("title", "").strip() or os.path.splitext(filename)[0].replace("_", " ").title()
    school_year = request.form.get("school_year", "2026 - 2027").strip()

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    # Ingest and Index
    user_id = session.get("user_id")
    username = session.get("username", "admin")
    ok, res = index_file(save_path, title=title, school_year=school_year, uploaded_by=username, user_id=user_id)

    if not ok:
        return jsonify({"success": False, "message": f"Lỗi xử lý tài liệu: {res}"}), 422

    return jsonify({
        "success": True,
        "message": f"Tải lên và lập chỉ mục thành công tài liệu: {title} ({res['total_chunks']} đoạn, {res['total_pages']} trang).",
        "document": res
    })

@app.route("/api/admin/documents/<int:doc_id>/status", methods=["PATCH"])
@admin_required
def admin_toggle_status(doc_id):
    data = request.get_json() or {}
    is_active = bool(data.get("is_active", True))
    user_id = session.get("user_id")
    username = session.get("username", "admin")

    ok, msg = toggle_document_status(doc_id, is_active, username=username, user_id=user_id)
    if not ok:
        return jsonify({"success": False, "message": msg}), 404

    return jsonify({"success": True, "message": msg})

@app.route("/api/admin/documents/<int:doc_id>", methods=["DELETE"])
@admin_required
def admin_delete_doc(doc_id):
    user_id = session.get("user_id")
    username = session.get("username", "admin")

    ok, msg = delete_document(doc_id, username=username, user_id=user_id)
    if not ok:
        return jsonify({"success": False, "message": msg}), 404

    return jsonify({"success": True, "message": msg})

@app.route("/api/admin/logs", methods=["GET"])
@admin_required
def admin_get_logs():
    limit = int(request.args.get("limit", 50))
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, user_id, username, action, target, details, ip_address, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        logs = [dict(r) for r in rows]
    return jsonify({"logs": logs})

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_get_users():
    with get_db() as conn:
        rows = conn.execute("SELECT id, username, full_name, role, created_at FROM users ORDER BY id ASC").fetchall()
        users = [dict(r) for r in rows]
    return jsonify({"users": users})

@app.route("/api/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    full_name = data.get("full_name", "").strip()
    role = data.get("role", "user").strip()

    if not username or not password or not full_name:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ thông tin tài khoản."}), 400

    if role not in ("admin", "user"):
        return jsonify({"success": False, "message": "Vai trò chỉ có thể là 'admin' hoặc 'user'."}), 400

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, generate_password_hash(password), full_name, role, datetime.now().isoformat())
            )
            conn.commit()
        log_audit(session.get("username"), "CREATE_USER", target=username, details=f"Created {role} account for {full_name}")
        return jsonify({"success": True, "message": f"Tạo tài khoản {username} thành công!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Không thể tạo tài khoản: {str(e)}"}), 400

# ================== FRONTEND PAGES ==================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
def admin_page():
    # If not logged in as admin, index.html modal handles login or redirect
    return render_template("admin.html")

@app.route("/stats")
def stats_legacy():
    """Backward compatibility API route."""
    if session.get("role") == "admin":
        return redirect("/api/admin/stats")
    return jsonify({"error": "Admin permission required."}), 403

@app.route("/stats-page")
def stats_page_legacy():
    """Backward compatibility page route."""
    return redirect("/admin")

@app.route("/upload", methods=["POST"])
def upload_legacy():
    """Backward compatibility upload route."""
    if session.get("role") != "admin":
        return jsonify({"message": "Chỉ Quản trị viên mới được tải tài liệu lên."}), 403
    return admin_upload_document()

@app.route("/ask", methods=["POST"])
def ask_legacy():
    """Backward compatibility ask route."""
    return api_ask()

if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 8080))
    print("\n" + "=" * 55)
    print("   SCHOOLWISE AI – CỐ VẤN NỘI QUY & THI ĐUA HỌC ĐƯỜNG")
    print("   Trường PTDTNT THCS & THPT Phước Sơn")
    print("=" * 55)
    print(f"  Trang chủ:       http://localhost:{port}")
    print(f"  Trang Quản trị:  http://localhost:{port}/admin")
    print("=" * 55 + "\n")

    serve(app, host="0.0.0.0", port=port, threads=8)
