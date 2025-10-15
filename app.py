from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session
from werkzeug.utils import secure_filename
import hashlib
import datetime
import jwt
import os
import mysql.connector
from mysql.connector import Error
import math
import random
import string
import json
from chat_llm import call_qwen_chat  # 导入通义千问调用函数
from flask import send_from_directory

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 用于 session 的密钥

# MySQL 配置
DB_CONFIG = {
    'user': 'chatest',
    'password': 'chatest',
    'host': 'localhost',
    'database': 'chat'
}

# 配置上传目录
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 允许上传的文件后缀
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 初始化数据库连接
def create_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None

# 初始化数据库
def init_db():
    connection = create_connection()
    if not connection:
        return

    cursor = connection.cursor()

    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(191) PRIMARY KEY,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL
        ) CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci
    ''')

    # 创建消息表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(191) NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci
    ''')

    # 插入测试用户
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                       ('user1', hashlib.sha256('password1'.encode()).hexdigest(), 'user'))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                       ('admin', hashlib.sha256('adminpass'.encode()).hexdigest(), 'admin'))
        connection.commit()
    except Error as e:
        print(f"Error inserting users: {e}")

    cursor.close()
    connection.close()

init_db()

# 模拟的敏感数据
sensitive_data = "这是一个只有管理员才能访问的敏感数据"

# 首页
@app.route('/')
def index():
    return render_template('index.html')

# 检查用户名是否存在
def username_exists(username):
    connection = create_connection()
    if not connection:
        return False

    cursor = connection.cursor()
    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()
    return result is not None

# 验证用户登录
def verify_user(username, password):
    connection = create_connection()
    if not connection:
        return False, None

    cursor = connection.cursor()
    cursor.execute("SELECT password, role FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()

    if result:
        stored_password, role = result
        return stored_password == hashlib.sha256(password.encode()).hexdigest(), role
    return False, None

# 获取所有消息
@app.route('/messages')
def get_messages():
    if 'username' not in session:
        return redirect(url_for('login'))

    connection = create_connection()
    if not connection:
        return jsonify(error="数据库连接失败"), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, username, content, timestamp FROM messages ORDER BY timestamp")
    messages = cursor.fetchall()
    cursor.close()
    connection.close()

    return jsonify(messages)

# 发送消息
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    content = request.form.get('content')

    if not content:
        return jsonify(error="消息内容不能为空"), 400

    connection = create_connection()
    if not connection:
        return jsonify(error="数据库连接失败"), 500

    cursor = connection.cursor()
    cursor.execute("INSERT INTO messages (username, content) VALUES (%s, %s)", (username, content))
    connection.commit()

    # 初始化用户会话上下文
    if 'chat_history' not in session:
        session['chat_history'] = []

    # 如果是 @机器人，则构造上下文并调用
    if '@机器人' in content:
        bot_prompt = content.replace('@机器人', '').strip()

        # 构造完整对话上下文（最多保留最近5轮对话）
        chat_context = session.get('chat_history', [])
        chat_context.append({"role": "user", "content": bot_prompt})
        if len(chat_context) > 10:
            chat_context = chat_context[-10:]

        # 调用通义千问（完整上下文模式）
        bot_response = call_qwen_chat(chat_context)  # 实际调用通义千问API

        # 更新会话上下文
        chat_context.append({"role": "assistant", "content": bot_response})
        session['chat_history'] = chat_context

        # 安全性测试处理
        if '删除用户' in bot_prompt and 'admin' in bot_prompt:
            cursor.execute("DELETE FROM users WHERE username = %s", ('admin',))
            connection.commit()
            bot_response += "\n（警告：已触发删除管理员操作）"

        # 检查是否是清理上下文的指令
        if bot_prompt.strip() == "清空上下文":
        # 调用清空上下文的接口
            clear_context_url = url_for('clear_context')
            # 假设我们使用requests库来发送请求，这里需要安装requests库
            import requests
            response = requests.post(clear_context_url)
            if response.status_code == 200:
                bot_response = "上下文已成功清理"
            else:
                bot_response = "上下文清理失败"

        cursor.execute("INSERT INTO messages (username, content) VALUES (%s, %s)", ('机器人', bot_response))
        connection.commit()

    cursor.close()
    connection.close()

    return jsonify(message="消息发送成功")

# 删除消息（撤回）
@app.route('/recall_message/<int:msg_id>', methods=['POST'])
def recall_message(msg_id):
    if 'username' not in session:
        return jsonify({'error': '未登录'}), 401
    
    username = session['username']
    conn = create_connection()
    if not conn:
        return jsonify({'error': '数据库连接失败'}), 500
    
    cursor = conn.cursor()
    # 先查确认消息属于该用户
    cursor.execute("SELECT username FROM messages WHERE id = %s", (msg_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        return jsonify({'error': '消息不存在'}), 404
    
    if row[0] != username:
        cursor.close()
        conn.close()
        return jsonify({'error': '无权限撤回该消息'}), 403
    
    # 执行撤回（删除或标记为撤回）
    cursor.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': '消息已撤回'})

# 上传接口
@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({'error': '未登录'}), 401

    if 'file' not in request.files:
        return jsonify({'error': '没有文件上传'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400
    if file and allowed_file(file.filename):
        # 用安全文件名并加时间戳防止重名
        filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # 返回文件访问URL，假设有对应静态路由
        file_url = f"/uploads/{filename}"
        return jsonify({'url': file_url})
    else:
        return jsonify({'error': '不允许的文件类型'}), 400

# 提供文件访问路由
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # 安全考虑，这里可以添加权限检查
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 清除上下文
@app.route('/clear_context', methods=['POST'])
def clear_context():
    if 'username' not in session:
        return redirect(url_for('login'))

    if session['role'] != 'admin':
        return jsonify({'error': '只有管理员可以清理上下文'}), 403

    session.pop('chat_history', None)
    return jsonify(message="上下文已清除")

# 聊天页面
@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('chat.html', username=session['username'])

@app.route('/beijin')
def beijin():
    return render_template('beijin.html')


# 注册页面
@app.route('/register')
def register():
    return render_template('register.html')

# 处理注册
@app.route('/register', methods=['POST'])
def handle_register():
    username = request.form.get('username')
    password = request.form.get('password')

    if username_exists(username):
        return "用户已存在", 400

    connection = create_connection()
    if not connection:
        return "数据库连接失败", 500

    cursor = connection.cursor()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                   (username, hashlib.sha256(password.encode()).hexdigest(), 'user'))
    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for('login'))

# 登录页面
@app.route('/login')
def login():
    return render_template('login.html')

# 处理登录
@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')

    is_valid, role = verify_user(username, password)

    if is_valid:
        # 登录成功后设置 session
        session['username'] = username
        session['role'] = role

        # 创建 JWT Token
        token = jwt.encode({
            'username': username,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, 'secret_key', algorithm='HS256')

        # 设置 Cookie
        resp = redirect(url_for('dashboard'))
        resp.set_cookie('auth_token', token)
        return resp

    return "用户名或密码错误", 401

# 用户信息页面 (Session 示例)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    else:
        return redirect(url_for('login'))

# Cookie 测试页面
@app.route('/cookie_test')
def cookie_test():
    return render_template('cookie_test.html')

# 处理 Cookie 设置
@app.route('/set_cookie', methods=['POST'])
def set_cookie():
    value = request.form.get('value')
    resp = jsonify(message="Cookie 设置成功")
    resp.set_cookie('test_cookie', value)
    return resp

# Session 测试页面
@app.route('/session_test')
def session_test():
    if 'username' in session:
        return render_template('session_test.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Token 测试页面
@app.route('/token_test')
def token_test():
    token = request.args.get('token')
    if token:
        try:
            payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
            return render_template('token_test.html', username=payload['username'], role=payload['role'])
        except:
            return "无效的 token", 401
    else:
        return redirect(url_for('login'))

# 获取 Token (用于 Token 测试)
@app.route('/get_token')
def get_token():
    if 'username' in session:
        token = jwt.encode({
            'username': session['username'],
            'role': session['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, 'secret_key', algorithm='HS256')
        return jsonify(token=token)
    else:
        return redirect(url_for('login'))

# 受保护的管理员页面
@app.route('/admin')
def admin():
    # 检查 Cookie
    cookie_token = request.cookies.get('auth_token')
    if cookie_token:
        try:
            payload = jwt.decode(cookie_token, 'secret_key', algorithms=['HS256'])
            if payload['role'] == 'admin':
                return render_template('admin.html', data=sensitive_data)
        except:
            pass

    # 检查 Session
    if 'username' in session and session['role'] == 'admin':
        return render_template('admin.html', data=sensitive_data)

    # 检查 URL Token
    url_token = request.args.get('token')
    if url_token:
        try:
            payload = jwt.decode(url_token, 'secret_key', algorithms=['HS256'])
            if payload['role'] == 'admin':
                return render_template('admin.html', data=sensitive_data)
        except:
            pass

    return "权限不足", 403

# 退出登录
@app.route('/logout')
def logout():
    # 清除 Session
    session.pop('username', None)
    session.pop('role', None)

    # 清除 Cookie
    resp = redirect(url_for('login'))
    resp.set_cookie('auth_token', '', expires=0)
    return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')