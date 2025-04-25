const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/game' });
const whiteKeys = ['P', 'N', 'B', 'R', 'Q', 'K'];
const blackKeys = ['p', 'n', 'b', 'r', 'q', 'k'];
const levelToElo = [500, 800, 950, 1100, 1250, 1400, 1550, 1700, 1850, 2000, 2150, 2300, 2450, 2600, 2750, 2900, 3050, 3200, 3350, 3500, 3600];
const { spawn } = require('child_process');

require('dotenv').config();

app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

PASSWORD = process.env.PASSWORD;
JWT_REGISTRATION_SECRET = crypto.randomBytes(32).toString('hex');
JWT_TOKEN_SECRET = PASSWORD;
K_FACTOR = 32;

const ip = process.env.HOST || 'localhost';
const activeGames = {};
const playerToGameMap = new Map();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.PASSWORD
  }
});

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

const generateResetCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

app.get('/verify', async (req, res) => {
  const { token } = req.query;

  try {
    jwt.verify(token, JWT_TOKEN_SECRET);

    res.json({ code: '0' });
  } catch (err) {
    res.status(400).send({ code: '1' });
  }
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const usernameRegex = /^[A-Za-z][A-Za-z0-9_]{2,14}$/;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex = /^[A-Za-z0-9_]{8,32}$/;

    if (!usernameRegex.test(username) || !emailRegex.test(email) || !passwordRegex.test(password)) {
      res.status(400).json({ error: '1' });
      return;
    }

    const usernameResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (usernameResult.rows.length !== 0) {
      if (usernameResult.rows[0].confirmed) {
        res.status(400).json({ error: '2' });
        return;
      } else {
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
      }
    }

    const emailResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (emailResult.rows.length !== 0) {
      if (emailResult.rows[0].confirmed) {
        res.status(400).json({ error: '3' });
        return;
      } else {
        await pool.query('DELETE FROM users WHERE email = $1', [email]);
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, email, password, profile_picture_url) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, 'uploads/' + username[0].toLowerCase() + '.png']
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_REGISTRATION_SECRET, { expiresIn: '5m' });

    const mailOptions = {
      from: 'bp.chessmate@gmail.com',
      to: email,
      subject: 'Confirm Your Registration',
      html: `
        <p>Hello ${username},</p>
        <p>Thank you for registering with ChessMate. Please confirm your email address by clicking the link below:</p>
        <a href="https://${ip}/confirm?token=${token}">Confirm Email</a>
        <p>If you did not register for ChessMate, please ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(201).json({ message: '0' });
  } catch (err) {
    res.status(500).json({ error: '4' });
  }
});

app.get('/confirm', async (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, JWT_REGISTRATION_SECRET);
    const userId = decoded.userId;
    await pool.query('UPDATE users SET confirmed = true WHERE id = $1', [userId]);

    res.send(`
      <h1>Email Confirmed!</h1>
      <p>Your email has been successfully confirmed. You can now log in to your account.</p>
    `);
  } catch (err) {
    res.status(400).send(`
      <h1>Failure to Confirm Email!</h1>
      <p>Your email couldn't be confirmed. Invalid or expired token.</p>
    `);
  }
});

app.get('/data', async (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, JWT_TOKEN_SECRET);
    const userId = decoded.userId;
    const data = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

    res.send({ message: data.rows[0] });
  } catch (err) {
    res.status(400).send({ error: '0' });
  }
});

app.get('/player', async (req, res) => {
  const { playerId } = req.query;

  try {
    const data = await pool.query('SELECT * FROM users WHERE id = $1', [playerId]);

    res.send({ message: data.rows[0] });
  } catch (err) {
    res.status(400).send({ error: '0' });
  }
});

app.get('/game', async (req, res) => {
  const { gameId } = req.query;

  try {
    const data = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);

    res.send({ message: data.rows[0] });
  } catch (err) {
    res.status(400).send({ error: '0' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length > 0) {
      const user = result.rows[0];

      if (!user.confirmed) {
        return res.status(400).json({ error: '1' });
      }

      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: user.id }, JWT_TOKEN_SECRET, { expiresIn: '1d' });
        res.json({ message: token });
      } else {
        res.status(400).json({ error: '2' });
      }
    } else {
      res.status(400).json({ error: '3' });
    }
  } catch (err) {
    res.status(500).json({ error: '4' });
  }
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const resetPswCode = generateResetCode();
      const resetPswExpires = new Date(Date.now() + 5 * 60 * 1000);

      await pool.query(
        'UPDATE users SET reset_psw_code = $1, reset_psw_expires = $2 WHERE id = $3',
        [resetPswCode, resetPswExpires, user.id]
      );

      const mailOptions = {
        from: 'bp.chessmate@gmail.com',
        to: email,
        subject: 'Password Reset Code',
        html: `
          <p>Hello ${user.username},</p>
          <p>Your password reset code is: <strong>${resetPswCode}</strong></p>
          <p>This code will expire in 5 minutes.</p>
          <p>If you did not request this, please ignore this email.</p>
        `,
      };

      await transporter.sendMail(mailOptions);
      res.json({ message: '0' });
    } else {
      res.status(400).json({ error: '1' });
    }
  } catch (err) {
    res.status(500).json({ error: '2' });
  }
});

app.post('/reset', async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  try {
    const codeRegex = /^[0-9]{6}$/;
    const passwordRegex = /^[A-Za-z0-9_]{8,32}$/;

    if (!codeRegex.test(resetCode) || !passwordRegex.test(newPassword)) {
      res.status(400).json({ error: '1' });
      return;
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      res.status(400).json({ error: '2' });
      return;
    }

    const user = result.rows[0];

    if (user.reset_psw_code !== resetCode || new Date() > new Date(user.reset_psw_expires)) {
      res.status(400).json({ error: '3' });
      return;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      'UPDATE users SET password = $1, reset_psw_code = NULL, reset_psw_expires = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );

    res.json({ message: '0' });
  } catch (err) {
    res.status(500).json({ error: '4' });
  }
});

app.post('/update', express.json(), (req, res) => {
  try {
    const { token, image, filename, description } = req.body;
    
    if (!image || !filename) {
      return res.status(400).json({ error: '1' });
    }

    if (!/^data:image\/(jpeg|png);base64,/.test(image) && !/^[A-Za-z0-9+/]+={0,2}$/.test(image)) {
      return res.status(400).json({ error: '1' });
    }

    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads');
    }

    const filePath = path.join('uploads', filename);
    
    fs.writeFile(filePath, buffer, (err) => {
      if (err) {
        return res.status(500).json({ error: '2' });
      }

      const decoded = jwt.verify(token, JWT_TOKEN_SECRET);
      const userId = decoded.userId;

      pool.query(
        'UPDATE users SET profile_picture_url = $1, description = $2 WHERE id = $3',
        [filePath, description, userId]
      );

      res.json({ message: '0' });
    });
  } catch (err) {
    res.status(500).json({ error: '3' });
  }
});

app.get('/uploads/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const imagePath = path.join(__dirname, 'uploads', filename);

    if (!fs.existsSync(imagePath)) {
      return res.status(404).json({ error: '1' });
    }

    const extname = path.extname(filename).toLowerCase();
    let contentType = (extname === '.png') ? 'image/png' : 'image/jpeg';
    res.setHeader('Content-Type', contentType);
    res.sendFile(imagePath);
  } catch (error) {
    res.status(500).json({ error: '2' });
  }
});

app.get('/games', (req, res) => {
  const { mode } = req.query;

  const gamesList = Object.keys(activeGames).filter(gameId => !activeGames[gameId].ai && activeGames[gameId].mode === mode && activeGames[gameId].state === 0 &&
    (activeGames[gameId].players['white'].ws || activeGames[gameId].players['black'].ws)).map(gameId => {
    const game = activeGames[gameId];
    let color;
    let opponent;
    let rating;

    if (game.players['white'].ws) {
      color = 'black';
      opponent = game.players['white'].name;
      rating = game.players['white'].rating;
    } else {
      color = 'white';
      opponent = game.players['black'].name;
      rating = game.players['black'].rating;
    }

    return {
      id: gameId,
      opponent: opponent,
      rating: rating,
      position: (game.startPosition === 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1' ? 'Standard' : 'Custom'),
      time: `${Math.floor(game.gameState.whiteTimer / 60)}+${game.increment}`,
      color: color.replace(color[0], color[0].toUpperCase())
    };
  });

  res.json(gamesList);
});

app.get('/archives', async (req, res) => {
  const { token } = req.query;
  const decoded = jwt.verify(token, JWT_TOKEN_SECRET);
  const userId = decoded.userId;
  const games = await pool.query('SELECT * FROM games WHERE white_player = $1 OR black_player = $1', [userId]);
  const gameRows = games.rows;

  for (let i = 0; i < gameRows.length; i++) {
    let user;

    if (gameRows[i].white_player === userId) {
      gameRows[i]['color'] = 'White';
      user = await pool.query('SELECT username, bullet_rating, blitz_rating, rapid_rating, classical_rating FROM users WHERE id = $1', [gameRows[i].black_player]);
    } else {
      gameRows[i]['color'] = 'Black';
      user = await pool.query('SELECT username, bullet_rating, blitz_rating, rapid_rating, classical_rating FROM users WHERE id = $1', [gameRows[i].white_player]);
    }

    user = user.rows[0];
    gameRows[i]['user'] = user.username;
    const timeControl = gameRows[i].time_control

    if (['60+0', '120+1', '180+0'].includes(timeControl)) {
      gameRows[i]['rating'] = user.bullet_rating;
    } else if (['180+2', '300+0', '300+3'].includes(timeControl)) {
      gameRows[i]['rating'] = user.blitz_rating;
    } else if (['600+0', '600+5', '900+0'].includes(timeControl)) {
      gameRows[i]['rating'] = user.rapid_rating;
    } else if (['900+10', '1800+0', '1800+20'].includes(timeControl)) {
      gameRows[i]['rating'] = user.classical_rating;
    }
  }

  res.json(gameRows);
});

app.get('/analyse', async (req, res) => {
  const { fen, moves } = req.query;
  const sf = spawn('./stockfish');
  let analysis;
  
  sf.stdin.write('uci\n');
  sf.stdin.write(`position fen ${fen} moves ${moves}\n`);
  
  sf.stdout.on('data', (data) => {
    const msg = data.toString();

    if (msg.includes('bestmove')) {
      analysis = 'bestmove' + msg.split('bestmove')[1].split('\r\n')[0];
      sf.stdin.write('quit\n');
      res.json(analysis);
    }
  });
  
  sf.stdin.write(`go depth 18\n`);
});

app.post('/create', (req, res) => {
  const { position, type, timeControl, gameMode, difficulty } = req.body;
  const rawPos = position.trim().split(' ')[0];
  let modifiedPos = '';
  let x = 0;
  let y = 0;
  let whiteKing = false;
  let blackKing = false;
  let responded = false;

  for (let char of rawPos) {
    if (x < 8) {
      if (whiteKeys.includes(char) || blackKeys.includes(char)) {
        x++;
        modifiedPos += char;

        if (char === 'k') {
          if (blackKing) {
            res.status(400).json('1');
            return;
          } else {
            blackKing = true;
          }
        } else if (char === 'K') {
          if (whiteKing) {
            res.status(400).json('1');
            return;
          } else {
            whiteKing = true;
          }
        }
      } else if (['1', '2', '3', '4', '5', '6', '7', '8'].includes(char)) {
        const curr = x;
        x += char;
        modifiedPos += (x < 9 ? char : (8 - curr));
      }
    }

    if (char === '/') {
      modifiedPos += char;
      x = 0;
      y++;

      if (y > 7) {
        break;
      }
    }
  }

  if (!whiteKing || !blackKing) {
    res.status(400).json('1');
    return;
  }

  if (x < 8) {
    modifiedPos += (8 - x);
    x = 8;
  }

  while (y < 7) {
    if (modifiedPos.length > 0 && modifiedPos[modifiedPos.length - 1] !== '/') {
      modifiedPos += '/';
    }

    modifiedPos += '8';
    y++;
  }

  const rows = modifiedPos.split('/');

  if (rows[0].includes('p') || rows[0].includes('P') || rows[7].includes('p') || rows[7].includes('P')) {
    res.status(400).json('1');
    return;
  }

  const timeout = setTimeout(() => {
    if (responded) return;
    responded = true;
    res.status(400).json('1');
    return;
  }, 2000);

  const sf = spawn('./stockfish');

  sf.stdin.write('uci\n');
  sf.stdin.write(`position fen ${modifiedPos} w - - 0 1\n`);

  sf.stdout.on('data', (data) => {
    if (responded) return;
    const msg = data.toString();

    if (msg.includes('bestmove (none)')) {
      sf.stdin.write('quit\n');
      clearTimeout(timeout);
      responded = true;
      res.status(400).json('1');
      return;
    } else if (msg.includes('bestmove')) {
      sf.stdin.write('quit\n');
      const [minutes, increment] = timeControl.split('+').map(Number);
      const gameId = generateGameId();
      activeGames[gameId] = new ChessGame(type, minutes * 60, increment, gameMode, difficulty);

      if (modifiedPos !== 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR') {
        activeGames[gameId].setPosition(modifiedPos);
      }
      
      clearTimeout(timeout);
      responded = true;
      res.json(gameId);
      return;
    }
  });

  sf.stdin.write(`go depth 2\n`);
});

app.get('/fetch', async (req, res) => {
  const { archive } = req.query;
  const games = await pool.query('SELECT * FROM games WHERE id = $1', [archive]);
  const game = games.rows[0];
  const whitePlayers = await pool.query('SELECT * FROM users WHERE id = $1', [game.white_player]);
  const whitePlayer = whitePlayers.rows[0];
  const blackPlayers = await pool.query('SELECT * FROM users WHERE id = $1', [game.black_player]);
  const blackPlayer = blackPlayers.rows[0];
  const moveData = await pool.query('SELECT * FROM moves WHERE game = $1', [archive]);
  const moves = moveData.rows;
  moves.sort((a, b) => a.move_number - b.move_number);

  res.json({ game: { game, whitePlayer, blackPlayer, moves } });
});

class ChessGame {
  constructor(type, time, increment, mode, difficulty) {
    this.startPosition = 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1';
    this.players = { 'white': { ws: null, name: '', image: '', rating: 0 }, 'black': { ws: null, name: '', image: '', rating: 0 } };
    this.ai = type === 'ai' ? true : false;
    this.stockfish = null;
    this.aiDifficulty = difficulty;
    this.whiteDrawOffer = false;
    this.blackDrawOffer = false;
    this.gameState = {
      board: [
        ['r', 'n', 'b', 'q', 'k', 'b', 'n', 'r'],
        ['p', 'p', 'p', 'p', 'p', 'p', 'p', 'p'],
        ['' , '' , '' , '' , '' , '' , '' , '' ],
        ['' , '' , '' , '' , '' , '' , '' , '' ],
        ['' , '' , '' , '' , '' , '' , '' , '' ],
        ['' , '' , '' , '' , '' , '' , '' , '' ],
        ['P', 'P', 'P', 'P', 'P', 'P', 'P', 'P'],
        ['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R']
      ],
      currentTurn: 'white',
      winner: null,
      whiteTimer: time,
      blackTimer: time,
      capturedWhite: [],
      capturedBlack: [],
      lastMoveStart: null,
      lastMoveTarget: null,
      whiteKingside: false,
      blackKingside: false,
      whiteQueenside: false,
      blackQueenside: false
    };
    this.timerInterval = null;
    this.increment = increment;
    this.mode = mode;
    this.time = time;
    this.moveHistory = [];
    this.boardHistory = [JSON.stringify(this.gameState.board)];
    this.moveCounter = 0;
    this.state = 0;
  }

  setPosition(position) {
    let castleRights = 'KQkq';

    const board = [
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', '']
    ];

    let i = 0;

    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        if (['1', '2', '3', '4', '5', '6', '7', '8'].includes(position[i])) {
          x += position[i];
          x--;
        } else if (whiteKeys.includes(position[i]) || blackKeys.includes(position[i])) {
          board[y][x] = position[i];
        }

        if (y === 0 && x === 0 && position[i] !== 'r') {
          castleRights = castleRights.replace('q', '');
          this.gameState.blackQueenside = true;
        } else if (y === 0 && x === 4 && position[i] !== 'k') {
          castleRights = castleRights.replace('kq', '');
          this.gameState.blackQueenside = true;
          this.gameState.blackKingside = true;
        } else if (y === 0 && x === 7 && position[i] !== 'r') {
          castleRights = castleRights.replace('k', '');
          this.gameState.blackKingside = true;
        } else if (y === 7 && x === 0 && position[i] !== 'R') {
          castleRights = castleRights.replace('Q', '');
          this.gameState.whiteQueenside = true;
        } else if (y === 7 && x === 4 && position[i] !== 'K') {
          castleRights = castleRights.replace('KQ', '');
          this.gameState.whiteQueenside = true;
          this.gameState.whiteKingside = true;
        } else if (y === 7 && x === 7 && position[i] !== 'R') {
          castleRights = castleRights.replace('K', '');
          this.gameState.whiteKingside = true;
        }

        i++;

        if (position[i] === '/') {
          i++;
        }
      }
    }

    this.startPosition = position + ' w ' + (castleRights ? castleRights : '-') + ' - 0 1';
    this.gameState.board = board;
  }

  initStockfish() {
    this.stockfish = spawn('./stockfish');
    this.stockfish.stdin.write('uci\n');
    this.stockfish.stdin.write('setoption name Skill Level value ' + this.aiDifficulty + '\n');
    this.stockfish.stdin.write(`position fen ${this.startPosition}\n`);
    
    this.stockfish.stdout.on('data', (data) => {
      const msg = data.toString();

      if (msg.includes('bestmove')) {
        const bestMove = msg.split('bestmove ')[1].split(' ')[0];
        this.handleAIMove(bestMove);
      }
    });
  }

  handleAIMove(move) {
    const fromCol = move.charCodeAt(0) - 'a'.charCodeAt(0);
    const fromRow = 8 - parseInt(move[1], 10);
    const toCol = move.charCodeAt(2) - 'a'.charCodeAt(0);
    const toRow = 8 - parseInt(move[3], 10);
    const promotion = move.length === 5 ? move[4] : null;
    
    const moveObj = {
      from: { row: fromRow, col: fromCol },
      to: { row: toRow, col: toCol },
      promotion
    };
    
    this.handleMessage(this.players['black'], { 
      type: 'move', 
      ...moveObj
    });
  }

  toUCINotation(move) {
    const files = ['a','b','c','d','e','f','g','h'];
    const fromFile = files[move.from.col];
    const fromRank = 8 - move.from.row;
    const toFile = files[move.to.col];
    const toRank = 8 - move.to.row;
    const promotion = move.promotion ? move.promotion.toLowerCase() : '';

    return `${fromFile}${fromRank}${toFile}${toRank}${promotion}`;
  }

  updateCastleing(selectedPiece, row, col) {
    if (selectedPiece.row == 7 && selectedPiece.col == 4 ||  row == 7 && col == 4) {
      this.gameState.whiteKingside = true;
      this.gameState.whiteQueenside = true;
      this.moveCounter = 0;
    } else if (selectedPiece.row == 7 && selectedPiece.col == 0 ||  row == 7 && col == 0) {
      this.gameState.whiteQueenside = true;
      this.moveCounter = 0;
    } else if (selectedPiece.row == 7 && selectedPiece.col == 7 ||  row == 7 && col == 7) {
      this.gameState.whiteKingside = true;
      this.moveCounter = 0;
    } else if (selectedPiece.row == 0 && selectedPiece.col == 4 || row == 0 && col == 4) {
      this.gameState.blackKingside = true;
      this.gameState.blackQueenside = true;
      this.moveCounter = 0;
    } else if (selectedPiece.row == 0 && selectedPiece.col == 0 || row == 0 && col == 0) {
      this.gameState.blackQueenside = true;
      this.moveCounter = 0;
    } else if (selectedPiece.row == 0 && selectedPiece.col == 7 || row == 0 && col == 7) {
      this.gameState.blackKingside = true;
      this.moveCounter = 0;
    }
  }

  isSquareUnderAttack(row, col, boardState, isWhite) {
    for (let r = 0; r < 8; r++) {
      for (let c = 0; c < 8; c++) {
        const piece = boardState[r][c];

        if (piece && (isWhite ? blackKeys.includes(piece) : whiteKeys.includes(piece))) {
          const moves = this.getLegalMoves(r, c, piece, boardState, true, false);

          if (moves.some(move => move.row === row && move.col === col)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  simulateMove(boardState, from, to) {
    const newBoard = boardState.map((row) => [...row]);
    const piece = newBoard[from.row][from.col];
    newBoard[from.row][from.col] = '';
    newBoard[to.row][to.col] = piece;

    return newBoard;
  }

  isInCheck(boardState, isWhite) {
    const king = isWhite ? 'K' : 'k';
    let kingRow = -1;
    let kingCol = -1;

    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 8; col++) {
        if (boardState[row][col] === king) {
          kingRow = row;
          kingCol = col;
          break;
        }
      }

      if (kingRow !== -1) break;
    }

    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 8; col++) {
        const piece = boardState[row][col];

        if (piece && (this.gameState.currentTurn === 'white' ? blackKeys.includes(piece) : whiteKeys.includes(piece))) {
          const moves = this.getLegalMoves(row, col, piece, boardState, true, false);

          if (moves.some((move) => move.row === kingRow && move.col === kingCol)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  isInCheckmate(boardState, isWhite) {
    if (!this.isInCheck(boardState, isWhite)) {
      return false;
    }

    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 8; col++) {
        const piece = boardState[row][col];

        if (piece && (isWhite ? whiteKeys.includes(piece) : blackKeys.includes(piece))) {
          const legalMoves = this.getLegalMoves(row, col, piece, boardState, false, true);

          if (legalMoves.length > 0) {
            return false;
          }
        }
      }
    }

    return true;
  }

  isInStalemate(boardState, isWhite) {
    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 8; col++) {
        const piece = boardState[row][col];

        if (piece && (isWhite ? whiteKeys.includes(piece) : blackKeys.includes(piece))) {
          const legalMoves = this.getLegalMoves(row, col, piece, boardState, false, true);

          if (legalMoves.length > 0) {
            return false;
          }
        }
      }
    }

    return !this.isInCheck(boardState, isWhite);
  }

  isThreefoldRepetition(boardState) {
    const boardString = JSON.stringify(boardState);
    this.boardHistory.push(boardString);
    const count = this.boardHistory.filter((state) => state === boardString).length;

    return count >= 3;
  }

  isFiftyMoveRule() {
    return this.moveCounter >= 100;
  }

  isInsufficientMaterial(boardState) {
    const pieces = boardState.flat().filter((piece) => piece !== '');

    if (pieces.length === 2) {
      return true;
    }

    if (pieces.length === 3 && (pieces.includes('B') || pieces.includes('b') || pieces.includes('N') || pieces.includes('n'))) {
      return true;
    }

    if (pieces.length >= 4) {
      if (!(pieces.includes('Q') || pieces.includes('q') || pieces.includes('R') || pieces.includes('r') ||
        pieces.includes('N') || pieces.includes('n') || pieces.includes('P') || pieces.includes('p'))) {
        let odd = false;
        let even = false;

        for (let row = 0; row < 8; row++) {
          for (let col = 0; col < 8; col++) {
            const piece = boardState[row][col];

            if (piece.toLowerCase() === 'b') {
              if ((row + col) % 2 === 0) {
                even = true;
              } else {
                odd = true;
              }
            }

            if (odd && even) return false;
          }
        }

        return true;
      }
    }

    return false;
  }

  isTimeoutDraw(boardState, isWhite) {
    const first_pieces = (isWhite ? boardState.flat().filter((piece) => whiteKeys.includes(piece)) : boardState.flat().filter((piece) => blackKeys.includes(piece)));
    const second_pieces = (isWhite ? boardState.flat().filter((piece) => blackKeys.includes(piece)) : boardState.flat().filter((piece) => whiteKeys.includes(piece)));

    if (second_pieces.length === 1) {
      return true;
    }

    let odd = false;
    let even = false;
    let bishopDraw = true;

    if (!(second_pieces.includes('q') || second_pieces.includes('r') || second_pieces.includes('n') || second_pieces.includes('p'))) {
      for (let row = 0; row < 8; row++) {
        for (let col = 0; col < 8; col++) {
          const piece = boardState[row][col];

          if (piece === 'b') {
            if ((row + col) % 2 === 0) {
              even = true;
            } else {
              odd = true;
            }
          }

          if (odd && even) {
            bishopDraw = false;
            break;
          }
        }

        if (!bishopDraw) break;
      }
    }

    if (second_pieces.length === 2 && !(second_pieces.includes('q') || second_pieces.includes('r') || second_pieces.includes('b') || second_pieces.includes('p')) || bishopDraw) {
      if (first_pieces.includes('Q') && !(first_pieces.includes('R') || first_pieces.includes('B') || first_pieces.includes('N') || first_pieces.includes('P'))) {
        return true;
      }

      if (second_pieces.includes('b') && first_pieces.includes('R') && !(first_pieces.includes('B') || first_pieces.includes('N') || first_pieces.includes('P'))) {
        return true;
      }
    }

    return false;
  }

  getLegalMoves(row, col, piece, boardState, capture, check) {
    const moves = [];
    const isWhite = piece === piece.toUpperCase();

    const isWithinBoard = (r, c) => r > -1 && r < 8 && c > -1 && c < 8;

    const canMoveTo = (r, c) => {
      const targetPiece = boardState[r][c];
      return !targetPiece || (isWhite ? targetPiece === targetPiece.toLowerCase() : targetPiece === targetPiece.toUpperCase());
    };

    const addMove = (r, c, e = false, p = null) => {
      if (isWithinBoard(r, c)) {
        moves.push({ row: r, col: c, ep: e, piece: p });
      }
    };

    switch (piece.toUpperCase()) {
      case 'P':
        const direction = isWhite ? -1 : 1;
        const startRow = isWhite ? 6 : 1;

        if (!capture && isWithinBoard(row + direction, col) && !boardState[row + direction][col]) {
          addMove(row + direction, col);

          if (row === startRow && !boardState[row + 2 * direction][col]) {
            addMove(row + 2 * direction, col);
          }
        }

        if (isWithinBoard(row + direction, col - 1) && boardState[row + direction][col - 1] && canMoveTo(row + direction, col - 1)) {
          addMove(row + direction, col - 1);
        }

        if (isWithinBoard(row + direction, col + 1) && boardState[row + direction][col + 1] && canMoveTo(row + direction, col + 1)) {
          addMove(row + direction, col + 1);
        }

        if (!capture && this.gameState.lastMoveStart && this.gameState.lastMoveTarget) {
          const { from, to } = { from: this.gameState.lastMoveStart, to: this.gameState.lastMoveTarget };
          const lastMovedPiece = boardState[to.row][to.col];

          if (lastMovedPiece.toLowerCase() === 'p' && Math.abs(from.row - to.row) === 2 && to.row === row && (to.col === col - 1 || to.col === col + 1)) {
            addMove(row + direction, to.col, true);
          }
        }

        break;
      case 'N':
        const knightMoves = [
          { row: row - 2, col: col - 1 },
          { row: row - 2, col: col + 1 },
          { row: row - 1, col: col - 2 },
          { row: row - 1, col: col + 2 },
          { row: row + 1, col: col - 2 },
          { row: row + 1, col: col + 2 },
          { row: row + 2, col: col - 1 },
          { row: row + 2, col: col + 1 },
        ];

        knightMoves.forEach((move) => {
          if (isWithinBoard(move.row, move.col) && canMoveTo(move.row, move.col)) {
            addMove(move.row, move.col);
          }
        });

        break;
      case 'B':
        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row + i, col + i)) break;

          if (boardState[row + i][col + i]) {
            if (canMoveTo(row + i, col + i)) addMove(row + i, col + i);
            break;
          }

          addMove(row + i, col + i);
        }

        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row + i, col - i)) break;

          if (boardState[row + i][col - i]) {
            if (canMoveTo(row + i, col - i)) addMove(row + i, col - i);
            break;
          }

          addMove(row + i, col - i);
        }

        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row - i, col + i)) break;

          if (boardState[row - i][col + i]) {
            if (canMoveTo(row - i, col + i)) addMove(row - i, col + i);
            break;
          }

          addMove(row - i, col + i);
        }

        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row - i, col - i)) break;

          if (boardState[row - i][col - i]) {
            if (canMoveTo(row - i, col - i)) addMove(row - i, col - i);
            break;
          }

          addMove(row - i, col - i);
        }

        break;
      case 'R':
        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row + i, col)) break;

          if (boardState[row + i][col]) {
            if (canMoveTo(row + i, col)) addMove(row + i, col);
            break;
          }

          addMove(row + i, col);
        }
        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row - i, col)) break;

          if (boardState[row - i][col]) {
            if (canMoveTo(row - i, col)) addMove(row - i, col);
            break;
          }

          addMove(row - i, col);
        }
        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row, col + i)) break;

          if (boardState[row][col + i]) {
            if (canMoveTo(row, col + i)) addMove(row, col + i);
            break;
          }

          addMove(row, col + i);
        }
        for (let i = 1; i < 8; i++) {
          if (!isWithinBoard(row, col - i)) break;

          if (boardState[row][col - i]) {
            if (canMoveTo(row, col - i)) addMove(row, col - i);
            break;
          }

          addMove(row, col - i);
        }

        break;
      case 'Q':
        this.getLegalMoves(row, col, isWhite ? 'R' : 'r', boardState, false, check).forEach((move) => addMove(move.row, move.col));
        this.getLegalMoves(row, col, isWhite ? 'B' : 'b', boardState, false, check).forEach((move) => addMove(move.row, move.col));
        break;
      case 'K':
        const kingMoves = [
          { row: row - 1, col: col - 1 },
          { row: row - 1, col: col },
          { row: row - 1, col: col + 1 },
          { row: row, col: col - 1 },
          { row: row, col: col + 1 },
          { row: row + 1, col: col - 1 },
          { row: row + 1, col: col },
          { row: row + 1, col: col + 1 },
        ];
      
        kingMoves.forEach((move) => {
          if (isWithinBoard(move.row, move.col) && canMoveTo(move.row, move.col)) {
            addMove(move.row, move.col);
          }
        });

        if (!capture) {
          if ((isWhite && !this.gameState.whiteKingside || !isWhite && !this.gameState.blackKingside) &&
            !boardState[row][col + 1] && !boardState[row][col + 2] &&
            !this.isSquareUnderAttack(row, col, boardState, isWhite) &&
            !this.isSquareUnderAttack(row, col + 1, boardState, isWhite) &&
            !this.isSquareUnderAttack(row, col + 2, boardState, isWhite)) {
            addMove(row, col + 2, false, col + 1);
          }
      
          if ((isWhite && !this.gameState.whiteQueenside || !isWhite && !this.gameState.blackQueenside) &&
            !boardState[row][col - 1] && !boardState[row][col - 2] && !boardState[row][col - 3] &&
            !this.isSquareUnderAttack(row, col, boardState, isWhite) &&
            !this.isSquareUnderAttack(row, col - 1, boardState, isWhite) &&
            !this.isSquareUnderAttack(row, col - 2, boardState, isWhite)) {
            addMove(row, col - 2, false, col - 1);
          }
        }

        break;
      default:
        break;
    }

    if (check) {
      const legalMoves = moves.filter((move) => {
        const newBoard = this.simulateMove(boardState, { row, col }, move);
        return !this.isInCheck(newBoard, isWhite);
      });

      return legalMoves;
    }

    return moves;
  }

  decrementTimer() {
    if (this.gameState.currentTurn === 'white') {
      this.gameState.whiteTimer--;
    } else {
      this.gameState.blackTimer--;
    }

    if (this.gameState.whiteTimer <= 0 || this.gameState.blackTimer <= 0) {
      if (this.isTimeoutDraw(this.gameState.board, this.gameState.currentTurn === 'white')) {
        this.gameState.winner = 'draw';
      } else {
        this.gameState.winner = this.gameState.whiteTimer <= 0 ? 'black' : 'white';
      }

      this.state = 2;
    }
  }

  startTimer() {
    this.timerInterval = setInterval(() => {
      this.decrementTimer();

      if (this.players['white'].ws) {
        this.players['white'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      }

      if (this.players['black'].ws) {
        this.players['black'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      }

      if (this.gameState.winner) {
        clearInterval(this.timerInterval);

        if (this.gameState.whiteTimer === '0' || this.gameState.blackTimer === '0') {
          this.archiveGame();
        }
      }
    }, 1000);
  }

  handleMessage(ws, data) {
    const communicatingPlayer = this.players['white'].ws === ws ? 'white' : 'black';

    if (data.type === 'move') {
      if (this.state !== 1) {
        return;
      }

      const { from, to, promotion } = data;
      const piece = this.gameState.board[from.row][from.col];

      if (piece && ((this.gameState.currentTurn === 'white' && piece === piece.toUpperCase()) || (this.gameState.currentTurn === 'black' && piece === piece.toLowerCase()))) {
        const legalMoves = this.getLegalMoves(from.row, from.col, piece, this.gameState.board, false, true);

        if (legalMoves.some(move => move.row === to.row && move.col === to.col)) {
          const capture = this.gameState.board[to.row][to.col];
          const epPiece = this.gameState.board[from.row][to.col];
          let isEP = false;
          this.gameState.lastMoveStart = { row: from.row, col: from.col };
          this.gameState.lastMoveTarget = { row: to.row, col: to.col };

          if (piece.toLowerCase() !== 'p' && !capture) {
            this.moveCounter++;
          } else {
            this.moveCounter = 0;
          }

          this.updateCastleing({ row: from.row, col: from.col, piece: piece }, to.row, to.col);

          if (capture) {
            if (this.gameState.currentTurn === 'white') {
              this.gameState.capturedWhite.push(capture);
            } else {
              this.gameState.capturedBlack.push(capture);
            }
          } else if (epPiece && epPiece.toLowerCase() === 'p' && legalMoves.some(move => move.ep && move.row === to.row && move.col === to.col)) {
            isEP = true;

            if (this.gameState.currentTurn === 'white') {
              this.gameState.capturedWhite.push(epPiece);
            } else {
              this.gameState.capturedBlack.push(epPiece);
            }
          }

          let promotionPiece = promotion;

          if (promotionPiece) {
            if (this.gameState.currentTurn === 'white' && !['Q', 'R', 'B', 'N'].includes(promotionPiece)) {
              promotionPiece = 'Q';
            } else if (this.gameState.currentTurn === 'black' && !['q', 'r', 'b', 'n'].includes(promotionPiece)) {
              promotionPiece = 'q';
            }
          }

          this.gameState.board[to.row][to.col] = promotionPiece || piece;
          this.gameState.board[from.row][from.col] = '';

          if (isEP) {
            this.gameState.board[from.row][to.col] = '';
          }

          if (legalMoves.some(move => move.piece === to.col - 1 && move.row === to.row && move.col === to.col)) {
            this.gameState.board[to.row][to.col - 1] = this.gameState.board[to.row][7];
            this.gameState.board[to.row][7] = '';
          } else if (legalMoves.some(move => move.piece === to.col + 1 && move.row === to.row && move.col === to.col)) {
            this.gameState.board[to.row][to.col + 1] = this.gameState.board[to.row][0];
            this.gameState.board[to.row][0] = '';
          }

          this.gameState.currentTurn === 'white' ? this.gameState.whiteTimer += this.increment : this.gameState.blackTimer += this.increment;
          this.gameState.currentTurn = this.gameState.currentTurn === 'white' ? 'black' : 'white';

          if (this.isInCheckmate(this.gameState.board, this.gameState.currentTurn === 'white')) {
            this.gameState.winner = this.gameState.currentTurn === 'white' ? 'black' : 'white';
            this.state = 2;
            this.archiveGame();
          } else if (this.isInStalemate(this.gameState.board, this.gameState.currentTurn === 'white')) {
            this.gameState.winner = 'draw';
            this.state = 2;
            this.archiveGame();
          } else if (this.isThreefoldRepetition(this.gameState.board)) {
            this.gameState.winner = 'draw';
            this.state = 2;
            this.archiveGame();
          } else if (this.isFiftyMoveRule()) {
            this.gameState.winner = 'draw';
            this.state = 2;
            this.archiveGame();
          } else if (this.isInsufficientMaterial(this.gameState.board)) {
            this.gameState.winner = 'draw';
            this.state = 2;
            this.archiveGame();
          }

          this.moveHistory.push(this.toUCINotation({ from, to, promotion }));

          if (this.players['white'].ws) {
            this.players['white'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
          }

          if (this.players['black'].ws) {
            this.players['black'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
          }

          if (this.ai && (this.players['black'].ws && this.gameState.currentTurn === 'white') || (this.players['white'].ws && this.gameState.currentTurn === 'black')) {
            this.stockfish.stdin.write(`position fen ${this.startPosition} moves ${this.moveHistory.join(' ')}\n`);
            this.stockfish.stdin.write('go movetime 1000\n');
          }
        }
      }
    } else if (data.type === 'offerDraw') {
      if (this.state !== 1) {
        return;
      }

      communicatingPlayer === 'white' ? this.whiteDrawOffer = true : this.blackDrawOffer = true;
  
      if (this.whiteDrawOffer && this.blackDrawOffer) {
        this.gameState.winner = 'draw';
        this.state = 2;
        this.archiveGame();
        this.players['white'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
        this.players['black'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      }
    } else if (data.type === 'resign') {
      if (this.state !== 1) {
        return;
      }

      this.gameState.winner = communicatingPlayer === 'white' ? 'black' : 'white';
      this.state = 2;
      this.archiveGame();
      this.players['white'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      this.players['black'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
    } else if (data.type === 'chat') {
      if (this.state === 0) {
        return;
      }

      this.players['white'].ws.send(JSON.stringify({ type: 'chat', message: this.players[communicatingPlayer].name + ': ' + data.message }));
      this.players['black'].ws.send(JSON.stringify({ type: 'chat', message: this.players[communicatingPlayer].name + ': ' + data.message }));
    }
  }

  handleDisconnect(ws) {
    if (this.players['white'].ws === ws) {
      this.players['white'].ws = null;

      if (this.players['black'].ws && !this.gameState.winner) {
        this.gameState.winner = 'black';
        this.state = 2;
        this.archiveGame();
        this.players['black'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      }
    } else if (this.players['black'].ws === ws) {
      this.players['black'].ws = null;

      if (this.players['white'].ws && !this.gameState.winner) {
        this.gameState.winner = 'white';
        this.state = 2;
        this.archiveGame();
        this.players['white'].ws.send(JSON.stringify({ type: 'gameState', gameState: this.gameState }));
      }
    }
  }

  archiveGame = async () => {
    let white;
    let black;
    let whiteBullet;
    let whiteBlitz;
    let whiteRapid;
    let whiteClassical;
    let blackBullet;
    let blackBlitz;
    let blackRapid;
    let blackClassical;

    if (this.players['white'].name) {
      const result = await pool.query('SELECT id, bullet_rating, blitz_rating, rapid_rating, classical_rating FROM users WHERE username = $1', [this.players['white'].name]);
      white = result.rows[0].id;
      whiteBullet = result.rows[0].bullet_rating;
      whiteBlitz = result.rows[0].blitz_rating;
      whiteRapid = result.rows[0].rapid_rating;
      whiteClassical = result.rows[0].classical_rating;
    }

    if (this.players['black'].name) {
      const result = await pool.query('SELECT id, bullet_rating, blitz_rating, rapid_rating, classical_rating FROM users WHERE username = $1', [this.players['black'].name]);
      black = result.rows[0].id;
      blackBullet = result.rows[0].bullet_rating;
      blackBlitz = result.rows[0].blitz_rating;
      blackRapid = result.rows[0].rapid_rating;
      blackClassical = result.rows[0].classical_rating;
    }

    if ((white && black) || this.ai) {
      if (this.ai) {
        if (white) {
          blackBullet = levelToElo[this.aiDifficulty];
          blackBlitz = levelToElo[this.aiDifficulty];
          blackRapid = levelToElo[this.aiDifficulty];
          blackClassical = levelToElo[this.aiDifficulty];
        } else {
          whiteBullet = levelToElo[this.aiDifficulty];
          whiteBlitz = levelToElo[this.aiDifficulty];
          whiteRapid = levelToElo[this.aiDifficulty];
          whiteClassical = levelToElo[this.aiDifficulty];
        }
      }

      let expectedWhite, expectedBlack, actualWhite, actualBlack, whiteRatingChange, blackRatingChange;

      switch (this.mode) {
        case 'Bullet':
          expectedWhite = 1 / (1 + 10 ** ((blackBullet - whiteBullet) / 400));
          expectedBlack = 1 - expectedWhite;

          if (this.gameState.winner === 'white') {
            actualWhite = 1;
            actualBlack = 0;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET bullet_wins = bullet_wins + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET bullet_losses = bullet_losses + 1 WHERE username = $1', [this.players['black'].name]);
          } else if (this.gameState.winner === 'black') {
            actualWhite = 0;
            actualBlack = 1;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (black) await pool.query('UPDATE users SET bullet_wins = bullet_wins + 1 WHERE username = $1', [this.players['black'].name]);
            if (white) await pool.query('UPDATE users SET bullet_losses = bullet_losses + 1 WHERE username = $1', [this.players['white'].name]);
          } else {
            actualWhite = 0.5;
            actualBlack = 0.5;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET bullet_draws = bullet_draws + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET bullet_draws = bullet_draws + 1 WHERE username = $1', [this.players['black'].name]);
          }

          if (white) await pool.query('UPDATE users SET bullet_rating = bullet_rating + $1 WHERE username = $2', [whiteRatingChange, this.players['white'].name]);
          if (black) await pool.query('UPDATE users SET bullet_rating = bullet_rating + $1 WHERE username = $2', [blackRatingChange, this.players['black'].name]);
          break;
        case 'Blitz':
          expectedWhite = 1 / (1 + 10 ** ((blackBlitz - whiteBlitz) / 400));
          expectedBlack = 1 - expectedWhite;

          if (this.gameState.winner === 'white') {
            actualWhite = 1;
            actualBlack = 0;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET blitz_wins = blitz_wins + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET blitz_losses = blitz_losses + 1 WHERE username = $1', [this.players['black'].name]);
          } else if (this.gameState.winner === 'black') {
            actualWhite = 0;
            actualBlack = 1;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (black) await pool.query('UPDATE users SET blitz_wins = blitz_wins + 1 WHERE username = $1', [this.players['black'].name]);
            if (white) await pool.query('UPDATE users SET blitz_losses = blitz_losses + 1 WHERE username = $1', [this.players['white'].name]);
          } else {
            actualWhite = 0.5;
            actualBlack = 0.5;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET blitz_draws = blitz_draws + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET blitz_draws = blitz_draws + 1 WHERE username = $1', [this.players['black'].name]);
          }

          if (white) await pool.query('UPDATE users SET blitz_rating = blitz_rating + $1 WHERE username = $2', [whiteRatingChange, this.players['white'].name]);
          if (black) await pool.query('UPDATE users SET blitz_rating = blitz_rating + $1 WHERE username = $2', [blackRatingChange, this.players['black'].name]);
          break;
        case 'Rapid':
          expectedWhite = 1 / (1 + 10 ** ((blackRapid - whiteRapid) / 400));
          expectedBlack = 1 - expectedWhite;

          if (this.gameState.winner === 'white') {
            actualWhite = 1;
            actualBlack = 0;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET rapid_wins = rapid_wins + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET rapid_losses = rapid_losses + 1 WHERE username = $1', [this.players['black'].name]);
          } else if (this.gameState.winner === 'black') {
            actualWhite = 0;
            actualBlack = 1;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (black) await pool.query('UPDATE users SET rapid_wins = rapid_wins + 1 WHERE username = $1', [this.players['black'].name]);
            if (white) await pool.query('UPDATE users SET rapid_losses = rapid_losses + 1 WHERE username = $1', [this.players['white'].name]);
          } else {
            actualWhite = 0.5;
            actualBlack = 0.5;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET rapid_draws = rapid_draws + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET rapid_draws = rapid_draws + 1 WHERE username = $1', [this.players['black'].name]);
          }

          if (white) await pool.query('UPDATE users SET rapid_rating = rapid_rating + $1 WHERE username = $2', [whiteRatingChange, this.players['white'].name]);
          if (black) await pool.query('UPDATE users SET rapid_rating = rapid_rating + $1 WHERE username = $2', [blackRatingChange, this.players['black'].name]);
          break;
        default:
          expectedWhite = 1 / (1 + 10 ** ((blackClassical - whiteClassical) / 400));
          expectedBlack = 1 - expectedWhite;

          if (this.gameState.winner === 'white') {
            actualWhite = 1;
            actualBlack = 0;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET classical_wins = classical_wins + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET classical_losses = classical_losses + 1 WHERE username = $1', [this.players['black'].name]);
          } else if (this.gameState.winner === 'black') {
            actualWhite = 0;
            actualBlack = 1;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (black) await pool.query('UPDATE users SET classical_wins = classical_wins + 1 WHERE username = $1', [this.players['black'].name]);
            if (white) await pool.query('UPDATE users SET classical_losses = classical_losses + 1 WHERE username = $1', [this.players['white'].name]);
          } else {
            actualWhite = 0.5;
            actualBlack = 0.5;
            whiteRatingChange = Math.round(K_FACTOR * (actualWhite - expectedWhite));
            blackRatingChange = Math.round(K_FACTOR * (actualBlack - expectedBlack));
            if (white) await pool.query('UPDATE users SET classical_draws = classical_draws + 1 WHERE username = $1', [this.players['white'].name]);
            if (black) await pool.query('UPDATE users SET classical_draws = classical_draws + 1 WHERE username = $1', [this.players['black'].name]);
          }

          if (white) await pool.query('UPDATE users SET classical_rating = classical_rating + $1 WHERE username = $2', [whiteRatingChange, this.players['white'].name]);
          if (black) await pool.query('UPDATE users SET classical_rating = classical_rating + $1 WHERE username = $2', [blackRatingChange, this.players['black'].name]);
      }

      const result = await pool.query('INSERT INTO games (white_player, black_player, result, time_control, starting_position) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [white ? white : (this.aiDifficulty + 1), black ? black : (this.aiDifficulty + 1), this.gameState.winner, this.time + '+' + this.increment, this.startPosition]);

      const game = result.rows[0].id;
      this.boardHistory.push(JSON.stringify(this.gameState.board));

      for (let i = 1; i < this.moveHistory.length + 1; i++) {
        await pool.query('INSERT INTO moves (game, move_number, uci, fen) VALUES ($1, $2, $3, $4)', [game, i, this.moveHistory[i-1], this.boardHistory[i]]);
      }
    }
  }
}

wss.on('connection', (ws, req) => {
  console.log('New client connected');
  const url = new URL(req.url, `https://${req.headers.host}`);
  const gameId = url.searchParams.get('gameId');
  const name = url.searchParams.get('name');
  const image = url.searchParams.get('image');
  const rating = url.searchParams.get('rating');
  let playerColor = url.searchParams.get('color');

  if (!activeGames[gameId]) {
    ws.send(JSON.stringify({ type: 'error', message: 'Game not found' }));

    return;
  }

  const game = activeGames[gameId];

  if (game.players['white'].ws && game.players['black'].ws) {
    ws.send(JSON.stringify({ type: 'error', message: 'Game is full' }));

    return;
  }

  if (!game.players['white'].ws && !game.players['black'].ws) {
    if (playerColor === 'random') {
      playerColor = Math.round(Math.random()) === 0 ? 'white' : 'black';
    }
  } else {
    playerColor = !game.players['white'].ws ? 'white' : 'black';
  }

  game.players[playerColor] = { ws: ws, name: name, image: image, rating: rating};
  playerToGameMap.set(ws, gameId);

  ws.send(JSON.stringify({ type: 'assignColor', color: playerColor }));

  const whitePlayer = game.players['white'];
  const blackPlayer = game.players['black'];

  if (whitePlayer.ws && blackPlayer.ws) {
    whitePlayer.ws.send(JSON.stringify({ type: 'setWhiteUser', whiteName: whitePlayer.name, whiteImage: whitePlayer.image, whiteRating: whitePlayer.rating }));
    whitePlayer.ws.send(JSON.stringify({ type: 'setBlackUser', blackName: blackPlayer.name, blackImage: blackPlayer.image, blackRating: blackPlayer.rating }));
    blackPlayer.ws.send(JSON.stringify({ type: 'setWhiteUser', whiteName: whitePlayer.name, whiteImage: whitePlayer.image, whiteRating: whitePlayer.rating }));
    blackPlayer.ws.send(JSON.stringify({ type: 'setBlackUser', blackName: blackPlayer.name, blackImage: blackPlayer.image, blackRating: blackPlayer.rating }));
  } else if (whitePlayer.ws) {
    whitePlayer.ws.send(JSON.stringify({ type: 'setWhiteUser', whiteName: whitePlayer.name, whiteImage: whitePlayer.image, whiteRating: whitePlayer.rating }));
  } else if (blackPlayer.ws) {
    blackPlayer.ws.send(JSON.stringify({ type: 'setBlackUser', blackName: blackPlayer.name, blackImage: blackPlayer.image, blackRating: blackPlayer.rating }));
  }
  
  ws.send(JSON.stringify({ type: 'gameState', gameState: game.gameState }));

  if (game.state === 0 && (game.players['white'].ws && game.players['black'].ws || game.ai)) {
    game.startTimer();
    game.state = 1;

    if (game.ai) {
      game.initStockfish();

      if (game.players['black'].ws) {
        blackPlayer.ws.send(JSON.stringify({ type: 'setWhiteUser', whiteName: 'Stockfish', whiteImage: 'https://' + ip + '/uploads/sf.png', whiteRating: levelToElo[game.aiDifficulty] }));
        game.stockfish.stdin.write(`go movetime 1000\n`);
      } else {
        whitePlayer.ws.send(JSON.stringify({ type: 'setBlackUser', blackName: 'Stockfish', blackImage: 'https://' + ip + '/uploads/sf.png', blackRating: levelToElo[game.aiDifficulty] }));
      }
    }
  }

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      const gameId = playerToGameMap.get(ws);

      if (!gameId) {
        ws.send(JSON.stringify({ type: 'error', message: 'Not in game' }));

        return;
      }

      const game = activeGames[gameId];

      if (!game) {
        ws.send(JSON.stringify({ type: 'error', message: 'Game not found' }));
        
        return;
      }

      game.handleMessage(ws, data);
    } catch (error) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
    const gameId = playerToGameMap.get(ws);

    if (gameId) {
      const game = activeGames[gameId];

      if (game) {
        game.handleDisconnect(ws);

        if (!game.players['white'].ws && !game.players['black'].ws) {
          game.state = 2;

          if (!game.gameState.winner) {
            game.gameState.winner = 'aborted';
          }
        }
      }

      delete activeGames[gameId];
      playerToGameMap.delete(ws);
    }
  });
});

function generateGameId() {
  return Math.random().toString(36).substring(2, 8);
}

server.listen(8080, () => {
  console.log('Server is listening');
});