const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-pds-key';

// 메모리 DB (실제 서비스 시 Supabase / MongoDB 등 연동)
const users = [];   // { id, email, password }
const todos = [];   // { id, userId, title, dueDate, priority, completed, ... }

// [인증 미들웨어] 토큰 검증
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
    }
    req.user = user; // { userId, email }
    next();
  });
}

// 1. 회원가입 API (POST /api/auth/signup)
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력해주세요.' });

  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ error: '이미 존재하는 계정입니다.' });

  // bcrypt 암호화 (Salt Round: 12)
  const hashedPassword = await bcrypt.hash(password, 12);
  const newUser = { id: `user_${Date.now()}`, email, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: '회원가입 완료', userId: newUser.id });
});

// 2. 로그인 API (POST /api/auth/login)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });

  // JWT 토큰 발급 (1시간 유효)
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: '로그인 성공', token, user: { id: user.id, email: user.email } });
});

// 3. 내 할 일(Todo) 목록 조회 (GET /api/todos)
app.get('/api/todos', authenticateToken, (req, res) => {
  // 본인의 userId 데이터만 추출하여 반환 (타 유저 차단)
  const myTodos = todos.filter(t => t.userId === req.user.userId);
  res.json(myTodos);
});

// 4. 내 할 일 추가 (POST /api/todos)
app.post('/api/todos', authenticateToken, (req, res) => {
  const newTodo = {
    id: Date.now(),
    userId: req.user.userId,
    ...req.body
  };
  todos.push(newTodo);
  res.status(201).json(newTodo);
});

// 5. 내 할 일 삭제 (DELETE /api/todos/:id)
app.delete('/api/todos/:id', authenticateToken, (req, res) => {
  const todoId = Number(req.params.id);
  const index = todos.findIndex(t => t.id === todoId);

  if (index === -1) return res.status(404).json({ error: '데이터를 찾을 수 없습니다.' });
  
  // 남의 자료 삭제 시도 시 403 Forbidden 거절
  if (todos[index].userId !== req.user.userId) {
    return res.status(403).json({ error: '타인의 자료는 삭제할 수 없습니다.' });
  }

  todos.splice(index, 1);
  res.json({ message: '삭제 완료' });
});

module.exports = app;