const express = require('express');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, 'loans.db');
let db = null;


const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(4001, () => {
      console.log('Server running at http://localhost:4001/');
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// Register Route
app.post("/api/user/register", async (request, response) => {
  const { email, username, password, role } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const selectUserQuery = `SELECT * FROM users WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);

  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO users (email, username, password, role) 
      VALUES (?, ?, ?, ?)
    `;
    const dbResponse = await db.run(createUserQuery, [email, username, hashedPassword, role]);
    const newUserId = dbResponse.lastID;
    response.status(201).send(`Created new user with ID: ${newUserId}`);
  } else {
    response.status(400).send("Username already exists");
  }
});

// Login Route
app.post("/api/user/login", async (request, response) => {
  const { username, password } = request.body;

  const selectUserQuery = `SELECT * FROM users WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);

  if (dbUser === undefined) {
    return response.status(400).json({ error: "Invalid User" });

  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
    
      const payload = {
        username: dbUser.username,
        email: dbUser.email,
        role:dbUser.role,
        id: dbUser.id,  
      };
console.log(dbUser.id)
      const jwtToken = jwt.sign(payload, "my_secret_code", { expiresIn: '1h' });
      return response.send({ jwtToken ,role: dbUser.role,id:dbUser.id});
    } else {
      return response.status(400).json({ error: "Invalid Password" });

    }
  }
});

// Middleware 
 const authenticateToken = (request, response, next) => {
   // console.log("token")
  try {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    // console.log(token)

    if (!token) return response.sendStatus(401);

    jwt.verify(token, "my_secret_code", (err, user) => {
      if (err) return response.sendStatus(403);
      request.userId = user.id;
      console.log("99")
      next();
    });
  } catch (error) {
    console.error("Auth error:", error);
    response.status(500).json({ error: 'Authentication failed.' });
  }
}; 

// Loan Application Route
app.post("/apply-loan", authenticateToken, async (req, res) => {
  const {
    name,
    loanTenure,
    reason,
    amount,
    employmentStatus,
    employmentAddress,
  } = req.body;
console.log(116)
  const userId = req.userId; 

  if (!name || !loanTenure || !reason || !amount || !employmentStatus || !employmentAddress) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
  
    const findVerifier = `SELECT id, username FROM users WHERE role = 'verifier' LIMIT 1`;
    const verifier = await db.get(findVerifier);
console.log(verifier)
    if (!verifier) {
      return res.status(500).json({ message: "No verifier available" });
    }
    const pendingOfficerName=verifier.username
    const pendingOfficerId=verifier.id
    
    const insertQuery = `
      INSERT INTO loan_applications 
      (userId, name, loanTenure, reason, amount, employmentStatus, employmentAddress,pendingOfficerName, pendingOfficerId)
      VALUES (?, ?, ?, ?, ?, ?, ?,?,?)
    `;

    const result = await db.run(insertQuery, [
      userId,
      name,
      loanTenure,
      reason,
      amount,
      employmentStatus,
      employmentAddress,
	  pendingOfficerName, 
      pendingOfficerId
    ]);

    res.status(201).json({
      applicationId: result.lastID,
                assigned_to: verifier.name,
                message: 'Loan application submitted and assigned to a verifier'
    });
  } catch (err) {
    console.error("Loan Apply Error:", err.message);
    res.status(500).json({ error: "Failed to submit loan application" });
  }
});




      

app.get('/user/loan-overview/:userId', async (req, res) => {
  const userId = req.params.userId;
console.log('s')
  const totalsQuery = `
    SELECT 
      IFNULL(SUM(l.amount), 0) AS total_loan,
      IFNULL(SUM(r.amount), 0) AS total_repaid,
      (IFNULL(SUM(l.amount), 0) - IFNULL(SUM(r.amount), 0)) AS pending_amount
    FROM loan_applications l
    LEFT JOIN repayments r ON l.id = r.loan_id
    WHERE l.userId = ?
  `;
 // console.log('s')
  const loanBreakdownQuery = `
    SELECT 
      l.id AS loan_id,
      l.loanTenure,
      l.amount,
      l.reason,
      l.status,
      l.created_at,
      l.pendingOfficerName,
      l.pendingOfficerId,
      l.name,
      IFNULL(SUM(r.amount), 0) AS repaid_amount,
      (l.amount - IFNULL(SUM(r.amount), 0)) AS pending_amount
    FROM loan_applications l
    LEFT JOIN repayments r ON l.id = r.loan_id
    WHERE l.userId = ?
    GROUP BY l.id
    ORDER BY l.created_at DESC
  `;

  try {
    const totals = await db.get(totalsQuery, [userId]);
    const loans = await db.all(loanBreakdownQuery, [userId]);

    res.json({
      user_id: userId,
      total_loan: totals.total_loan,
      total_repaid: totals.total_repaid,
      total_pending: totals.pending_amount,
      loans: loans
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/verifier/dashboard', async (req, res) => {
  

  try {
    const [
      recentApplications,
      { approvedLoanCount = 0 } = {},
      { fullyRepaidLoanCount = 0 } = {},
      { borrowersWithPendingLoans = 0 } = {},
      { totalAmountReceived = 0 } = {},
      { totalAmountDisbursed = 0 } = {},
      { totalSavings = 0 } = {}
    ] = await Promise.all([

  
      db.all(`
        SELECT id, userId,name, reason, amount, status, created_at
        FROM loan_applications
        ORDER BY created_at DESC
      `),

     
      db.get(`
        SELECT COUNT(*) AS approvedLoanCount
        FROM loan_applications
        WHERE status = 'Approved'
      `),

      
      db.get(`
        SELECT COUNT(DISTINCT loan_id) AS fullyRepaidLoanCount
        FROM repayments
        WHERE is_fully_paid = 1
      `),

      db.get(`
        SELECT COUNT(DISTINCT userId) AS borrowersWithPendingLoans
        FROM loan_applications
        WHERE status = 'Approved'
        AND userId NOT IN (
          SELECT DISTINCT la.userId
          FROM loan_applications la
          JOIN repayments r ON la.id = r.loan_id
          WHERE r.is_fully_paid = 1
        )
      `),

      
      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalAmountReceived
        FROM repayments
      `),

      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalAmountDisbursed
        FROM loan_applications
        WHERE status = 'Approved'
      `),

      
      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalSavings
        FROM savings
      `)
    ]);

    res.json({
      recentApplications,
      approvedLoanCount,
      fullyRepaidLoanCount,
      borrowersWithPendingLoans,
      totalAmountReceived,
      totalAmountDisbursed,
      totalSavings
    });

  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.put('/verifier/verify-loan/:id', async (req, res) => {
 
  const loanId = req.params.id;

  try {
    
    const result = await db.run(`
      UPDATE loan_applications
      SET status = 'Verified'
      WHERE id = ? AND status = 'Pending'
    `, [loanId]);

    if (result.changes === 0) {
      return res.status(400).json({ message: 'Loan not found or not pending' });
    }

    res.json({ message: 'Loan verified successfully' });

  } catch (err) {
    console.error('Error verifying loan:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/user/loan-overview/:userId', async (req, res) => {
  const userId = req.params.userId;

  const checkUserQuery = `SELECT id FROM users WHERE id = ?`;
  const checkLoansQuery = `SELECT COUNT(*) as loan_count FROM loan_applications WHERE userId = ?`;

  try {
    
    const userExists = await db.get(checkUserQuery, [userId]);
    if (!userExists) {
      return res.status(404).json({ error: "User not found" });
    }

    
    const loanCheck = await db.get(checkLoansQuery, [userId]);
    if (loanCheck.loan_count === 0) {
      return res.status(204).json({ message: "User has no loan applications" }); 
    }

   
    const totalsQuery = `
      SELECT 
        IFNULL(SUM(l.amount), 0) AS total_loan,
        IFNULL(SUM(r.amount), 0) AS total_repaid,
        (IFNULL(SUM(l.amount), 0) - IFNULL(SUM(r.amount), 0)) AS pending_amount
      FROM loan_applications l
      LEFT JOIN repayments r ON l.id = r.loan_id
      WHERE l.userId = ?
    `;

    const loanBreakdownQuery = `
      SELECT 
        l.id AS loan_id,
        l.name,
        l.amount,
        l.reason,
        l.status,
        l.created_at,
        l.pending_with_officer_id, 
        l.pending_with_officer_name,
        IFNULL(SUM(r.amount), 0) AS repaid_amount,
        (l.amount - IFNULL(SUM(r.amount), 0)) AS pending_amount
      FROM loan_applications l
      LEFT JOIN repayments r ON l.id = r.loan_id
      WHERE l.userId = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `;

    const totals = await db.get(totalsQuery, [userId]);
    const loans = await db.all(loanBreakdownQuery, [userId]);

    res.json({
      user_id: userId,
      total_loan: totals.total_loan,
      total_repaid: totals.total_repaid,
      total_pending: totals.pending_amount,
      loans: loans
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.get('/admin/dashboard', async (req, res) => {
  try {
    const [
      recentApplications,
      { approvedLoanCount = 0 } = {},
      { fullyRepaidLoanCount = 0 } = {},
      { borrowersWithPendingLoans = 0 } = {},
      { totalAmountReceived = 0 } = {},
      { totalAmountDisbursed = 0 } = {},
      { totalSavings = 0 } = {},
      { totalUsers = 0 } = {}
    ] = await Promise.all([

      db.all(`
        SELECT id, userId, name, reason, amount, status, created_at
        FROM loan_applications
        ORDER BY created_at DESC
      `),

      db.get(`
        SELECT COUNT(*) AS approvedLoanCount
        FROM loan_applications
        WHERE status = 'Approved'
      `),

      db.get(`
        SELECT COUNT(DISTINCT loan_id) AS fullyRepaidLoanCount
        FROM repayments
        WHERE is_fully_paid = 1
      `),

      db.get(`
        SELECT COUNT(DISTINCT userId) AS borrowersWithPendingLoans
        FROM loan_applications
        WHERE status = 'Approved'
        AND userId NOT IN (
          SELECT DISTINCT la.userId
          FROM loan_applications la
          JOIN repayments r ON la.id = r.loan_id
          WHERE r.is_fully_paid = 1
        )
      `),

      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalAmountReceived
        FROM repayments
      `),

      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalAmountDisbursed
        FROM loan_applications
        WHERE status = 'Approved'
      `),

      db.get(`
        SELECT IFNULL(SUM(amount), 0) AS totalSavings
        FROM savings
      `),

      db.get(`
        SELECT COUNT(*) AS totalUsers
        FROM users
        WHERE role='user'
      `)
    ]);

    res.json({
      recentApplications,
      approvedLoanCount,
      fullyRepaidLoanCount,
      borrowersWithPendingLoans,
      totalAmountReceived,
      totalAmountDisbursed,
      totalSavings,
      totalUsers
    });

  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Internal server error' });
 }
});


app.put('/admin/verify-loan/:id', async (req, res) => {
  const loanId = req.params.id;
  const { status } = req.body;

  try {
    let result;

    if (status === "Verified") {
      result = await db.run(`
        UPDATE loan_applications
        SET status = 'Approved'
        WHERE id = ? AND status = 'Verified'
      `, [loanId]);
    } 
    elif  (status=="Pending"){
      result = await db.run(`
        UPDATE loan_applications
        SET status = 'Rejected'
        WHERE id = ? AND status != 'Verified'
      `, [loanId]);
    }

    if (result.changes === 0) {
      return res.status(400).json({ message: 'Loan not found or not in a valid state' });
    }

    res.json({ message: 'Loan status updated successfully' });

  } catch (err) {
    console.error('Error verifying loan:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});




