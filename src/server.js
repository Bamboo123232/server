process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  // Implement proper error logging here
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Implement proper error logging here
  process.exit(1);
});

// Add database connection error handling

require('dotenv').config();
const helmet = require('helmet');
const validPriceIds = {
  'price_1QsuAyIiC6XbCLF5JKd41qqo': 'Basic',
  'price_1QsuB9IiC6XbCLF5P6WFSnnU': 'Pro',
  'price_1QsuBIIiC6XbCLF53mPWP5ZI': 'Ultimate'
};
const express = require("express");
const app = express();
app.set('trust proxy', 1);
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // e.g., 'mail.yourdomain.com'
  port: process.env.EMAIL_PORT, // Common ports: 587 (TLS) or 465 (SSL)
  secure: process.env.EMAIL_SECURE, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER, // your full email address, e.g., 'support@yourdomain.com'
    pass: process.env.EMAIL_PASSWORD // your email password
  },
  tls: {
    rejectUnauthorized: false
  },
  debug: true // Enable debug logs
  
});

// Add transporter verification
transporter.verify(function(error, success) {
  if (error) {
    console.error('SMTP connection error:', error);
  } else {
    console.log('SMTP server is ready to take our messages');
  }
});
const mysql = require('mysql2/promise');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('./middleware/auth');
const fs = require('fs');
const path = require('path');
const PORT = process.env.PORT || 4242;
const YOUR_DOMAIN = process.env.DOMAIN || "https://e-protweaks.online";
const JWT_SECRET = process.env.JWT_SECRET;
const generateLicenseKey = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let license = 'PROTWEAKS-';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) license += '-';
    license += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return license;
};
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3380,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false
  }
});
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}); 
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}); 

app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS.split(','),
  methods: ['GET', 'POST'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use('/api/', apiLimiter);
app.use('/auth/login', loginLimiter);
app.use('/auth/register', registerLimiter)


// Routes start here
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt for email:', email); // Debug log
    
    const connection = await pool.getConnection();
    
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    console.log('Found users:', users.length); // Debug log

    if (users.length === 0) {
      connection.release();
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password validation result:', isPasswordValid); // Debug log

    if (!isPasswordValid) {
      connection.release();
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    
    

    const token = jwt.sign(
      { email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

  

    connection.release();
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/register', async (req, res) => {
  let connection;
  try {
    const { email, password } = req.body;
    connection = await pool.getConnection();
    
    // Check if user exists
    const [existingUsers] = await connection.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      connection.release();
      return res.status(400).json({ message: 'User already exists' });
    }

    // Generate token and hash password
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // First, create user with token
    await connection.execute(
      'INSERT INTO users (email, password, verification_token, verified) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, verificationToken, false]
    );

    // Generate JWT token for immediate access
    const token = jwt.sign(
      { email: email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Send verification email
    const verificationLink = `https://e-protweaks.online/verify-email?token=${verificationToken}`;
    await transporter.sendMail({
      from: `"PC Boost Pro" <${process.env.EMAIL_USER}>`, // Use your branded email
      to: email,
      subject: 'Verify your Protweaks Account',
      html: `
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            color: #ffffff;
            line-height: 1.5;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        .card {
            background: linear-gradient(to bottom, #111827, #000000);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        .header {
            padding: 40px 24px 24px;
            text-align: center;
        }
        
        .logo {
            margin: 0 auto 20px;
            width: 64px;
            height: 64px;
        }
        
        h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
            color: #ffffff;
        }
        
        .subtitle {
            color: #9ca3af;
            font-size: 16px;
        }
        
        .content {
            padding: 24px 32px 40px;
        }
        
        .verification-box {
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid #3b82f6;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            text-align: center;
        }
        
        .icon {
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
            color: #3b82f6;
        }
        
        p {
            margin-bottom: 16px;
            color: #9ca3af;
            font-size: 15px;
        }
        
        .email {
            font-weight: 500;
            color: #ffffff;
        }
        
        .btn {
            display: block;
            width: 100%;
            padding: 14px 24px;
            background-color: #2563eb;
            color: #ffffff;
            text-decoration: none;
            font-weight: 500;
            font-size: 16px;
            border-radius: 8px;
            text-align: center;
            margin: 32px 0;
        }
        
        .alt-link-container {
            background-color: #1f2937;
            border-radius: 8px;
            padding: 16px;
            margin-top: 24px;
            word-break: break-all;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
            color: #9ca3af;
        }
        
        .footer {
            padding: 24px 32px;
            text-align: center;
            font-size: 13px;
            color: #6b7280;
            border-top: 1px solid rgba(75, 85, 99, 0.4);
        }
        
        .expiry-note {
            margin-top: 24px;
            font-size: 13px;
            color: #6b7280;
            font-style: italic;
        }
        
        @media (max-width: 600px) {
            .container {
                padding: 20px 16px;
            }
            
            .content {
                padding: 24px 20px 32px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="logo">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                    </svg>
                </div>
                <h1>Verify Your Email</h1>
                <div class="subtitle">One more step to complete your registration</div>
            </div>
            
            <div class="content">
                <div class="verification-box">
                    <div class="icon">
                        <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                    </div>
                    <h2 style="font-size: 20px; font-weight: 600; color: #3b82f6; margin-bottom: 12px;">Email Verification Required</h2>
                    <p style="color: #d1d5db; margin-bottom: 0;">
                        Please verify your email address to access your dashboard.
                    </p>
                </div>
                
                <p>
                    We need to confirm your email address before you can access your account. Please click the button below to verify your email:
                </p>
                
                <a href="${verificationLink}" class="btn">Verify My Email →</a>
                
                <div class="expiry-note">
                    This verification link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.
                </div>
            </div>
            
            <div class="footer">
                <p>© 2024 Protweaks. All rights reserved.</p>
                <p style="margin-top: 8px;">

                </p>
            </div>
        </div>
    </div>
</body>
</html>
      `
    });
    console.log('Verification email sent successfully:', info.messageId);

    
    connection.release();
    res.status(201).json({ 
      message: 'Please check your email to verify your account',
      token: token, // Add this line
      email: email  // Add this line
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (connection) connection.release();
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
// Add email verification endpoint
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.log('Webhook Error:', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
    return;
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    
    // Retrieve the session with line items expanded
    const retrievedSession = await stripe.checkout.sessions.retrieve(session.id, {
      expand: ['line_items'],
    });
    
    const customerEmail = session.customer_details.email;
    const licenseKey = generateLicenseKey();
    const priceId = retrievedSession.line_items.data[0].price.id;
    const productName = validPriceIds[priceId] || 'Unknown Product';

    console.log('Payment successful!');
    console.log('Customer email:', customerEmail);
    console.log('Generated license key:', licenseKey);
    console.log('Price ID:', priceId);
    console.log('Product purchased:', productName);

    try {
      // Save to database first
      await saveLicenseToDatabase(customerEmail, productName, licenseKey);
      
      // Then send email
      await sendLicenseEmail(customerEmail, licenseKey, productName);
      console.log('Email sent successfully!');
    } catch (error) {
      console.error('Error in webhook:', error);
    }
  }

  res.json({received: true});
});
app.get('/auth/verify-email', async (req, res) => {
  let connection;
  try {
    const { token } = req.query;
    connection = await pool.getConnection();
    
    // First check if token exists and is valid - MODIFIED QUERY
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE verification_token = ?',
      [token]
    );

    if (users.length === 0) {
      // If no user found with this token, check if it might be already verified
      const [verifiedUsers] = await connection.execute(
        'SELECT * FROM users WHERE verification_token IS NULL AND verified = TRUE AND email = (SELECT email FROM users WHERE verification_token = ?)',
        [token]
      );
      
      if (verifiedUsers.length > 0) {
        const jwtToken = jwt.sign(
          { email: verifiedUsers[0].email },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        connection.release();
        return res.status(200).json({ 
          message: 'Email already verified',
          token: jwtToken,
          email: verifiedUsers[0].email
        });
      }
      
      connection.release();
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Check if already verified
    if (users[0].verified) {
      const jwtToken = jwt.sign(
        { email: users[0].email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      connection.release();
      return res.status(200).json({ 
        message: 'Email already verified',
        token: jwtToken,
        email: users[0].email
      });
    }

    // Begin transaction
    await connection.beginTransaction();

    try {
      // Update the database
      await connection.execute(
        'UPDATE users SET verified = TRUE, verification_token = NULL WHERE verification_token = ?',
        [token]
      );

      // Generate JWT token
      const jwtToken = jwt.sign(
        { email: users[0].email },
        JWT_SECRET,  // Instead of hardcoded 'ansdbgaskhjdhaisujhd'
        { expiresIn: '24h' }
      );
      
      // Commit the transaction
      await connection.commit();
      
      // Send success response with token
      res.status(200).json({ 
        message: 'Email verified successfully',
        token: jwtToken,
        email: users[0].email  // Add this line
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Verification error:', error);
    if (connection) connection.release();
    res.status(500).json({ message: 'Server error' });
  }
});
app.get('/auth/check-status', async (req, res) => {
  try {
    const { token } = req.query;
    const connection = await pool.getConnection();
    
    const [users] = await connection.execute(
      'SELECT verified FROM users WHERE email = (SELECT email FROM users WHERE verification_token = ? OR verification_token IS NULL)',
      [token]
    );
    
    connection.release();
    res.json({ verified: users[0]?.verified === 1 });
  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});
// Update the licenses endpoint to check for verified email
app.get('/api/licenses', auth, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Check if user is verified
    const [users] = await connection.execute(
      'SELECT verified FROM users WHERE email = ?',
      [req.userData.email]
    );
    
    if (!users[0]?.verified) {
      connection.release();
      return res.status(403).json({ message: 'Please verify your email first' });
    }
    
    // Fetch licenses
    const [licenses] = await connection.execute(
      'SELECT * FROM licenses WHERE email = ? ORDER BY purchase_date DESC',
      [req.userData.email]
    );
    
    connection.release();
    res.json(licenses);
  } catch (error) {
    console.error('Error fetching licenses:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Add connection test
pool.getConnection()
  .then(connection => {
    console.log('Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('Error connecting to the database:', err);
  });


// Email sending function
const sendLicenseEmail = async (customerEmail, licenseKey, productName) => {
  const mailOptions = {
    from: `"PC Boost Pro" <${process.env.EMAIL_USER}>`, // Use your branded email
    to: customerEmail,
    subject: 'Your PC Boost Pro License Key',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #4A90E2;">Thank you for your purchase!</h1>
        <p>Your order for <strong>${productName}</strong> has been confirmed.</p>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <h2 style="color: #333; margin-top: 0;">Your License Key:</h2>
          <p style="font-family: monospace; font-size: 18px; color: #4A90E2; background-color: #fff; padding: 10px; border-radius: 3px;">
            ${licenseKey}
          </p>
        </div>
        
        <p>To activate your software:</p>
        <ol>
          <li>Open PC Boost Pro</li>
          <li>Click on 'Activate License'</li>
          <li>Enter your license key</li>
          <li>Click 'Activate'</li>
        </ol>
        
        <p>If you need any assistance, please don't hesitate to contact our support team.</p>
        
        <p style="color: #666; font-size: 14px; margin-top: 30px;">
          Best regards,<br>
          The PC Boost Pro Team
        </p>
      </div>
    `
  };
  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully to:', customerEmail);
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};
// Add this function to save license to database
const saveLicenseToDatabase = async (email, tier, licenseKey) => {
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'INSERT INTO licenses (email, tier, license_key, purchase_date, used) VALUES (?, ?, ?, NOW(), ?)',
      [email, tier, licenseKey, false]
    );
    connection.release();
    console.log('License saved to database:', result.insertId);
    return result.insertId;
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  }
};
app.post("/create-checkout-session", async (req, res) => {
  const priceId = req.body.priceId;
  
  console.log('Received priceId:', priceId);
  
  if (!priceId) {
    return res.status(400).json({ error: 'Price ID is required' });
  }
  
  if (!validPriceIds[priceId]) {
    return res.status(400).json({ error: 'Invalid price ID' });
  }
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${YOUR_DOMAIN}?success=true`,
      cancel_url: `${YOUR_DOMAIN}?canceled=true`,
    });
  
    // Change this line from redirect to JSON response
    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update listen
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
