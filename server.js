// server.js
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import path from "path";
import session from "express-session";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(process.cwd())));

// Session configuration
app.use(session({
  secret: 'paste-aza-pro-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// 🔹 Supabase project settings
const SUPABASE_URL = "https://clykgtzngxomhrbvyooc.supabase.co";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNseWtndHpuZ3hvbWhyYnZ5b29jIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1OTQ5NDQ0MSwiZXhwIjoyMDc1MDcwNDQxfQ.gEZkkyalrauCqRqWf8RG1Xls_ZmR9xjgrozpcooCHco"; // service_role key
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ===============================
// Middleware
// ===============================

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.isLoggedIn) {
    next();
  } else {
    res.redirect('/login.html');
  }
};

// Middleware to check if user has a valid token
const hasValidToken = async (req, res, next) => {
  if (!req.session.isLoggedIn || !req.session.user) {
    return res.redirect('/login.html');
  }
  
  try {
    // Check if user has a valid token
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", req.session.user.id)
      .eq("valid", true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (error || !data || data.length === 0) {
      return res.redirect('/activate.html');
    }
    
    const token = data[0];
    
    // Check if token is expired
    if (token.expires_at && new Date(token.expires_at) < new Date()) {
      return res.redirect('/activate.html');
    }
    
    // Store token info in session
    req.session.token = token;
    next();
  } catch (err) {
    console.error("Token validation error:", err);
    res.redirect('/activate.html');
  }
};

// ===============================
// Authentication Routes
// ===============================

// Signup route
app.post("/api/signup", async (req, res) => {
  try {
    const { fullName, firstName, email, password } = req.body;
    
    // Use either fullName or firstName, whichever is provided
    const userFullName = fullName || firstName;
    
    console.log("Signup attempt:", { fullName: userFullName, email });
    
    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();
      
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User with this email already exists" });
    }
    
    // Validate required fields
    if (!userFullName) {
      return res.status(400).json({ success: false, message: "Full name is required" });
    }
    
    // Store user in database
    const { data: userData, error: userError } = await supabase
      .from("users")
      .insert([{ 
        fullName: userFullName, // Match the column name in the database
        email: email,
        password: password,
        role: 'user'
      }])
      .select();
    
    if (userError) {
      console.error("Supabase error:", userError);
      return res.status(400).json({ success: false, message: "Signup failed: " + userError.message });
    }
    
    res.json({ 
      success: true, 
      message: "Signup successful. Please activate your account with a token."
    });
  } catch (err) {
    console.error("❌ Error during signup:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check user credentials (using Supabase or local storage)
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .eq("password", password)
      .single();
    
    if (error || !data) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    
    // Set session
    req.session.isLoggedIn = true;
    req.session.user = {
      id: data.id,
      firstName: data.fullName,
      email: data.email,
      role: data.role
    };
    
    // Check if user has a valid token
    const { data: tokenData, error: tokenError } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", data.id)
      .eq("valid", true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    const hasValidToken = !tokenError && tokenData && tokenData.length > 0 && 
                         (!tokenData[0].expires_at || new Date(tokenData[0].expires_at) > new Date());
    
    res.json({ 
      success: true, 
      message: "Login successful", 
      user: { firstName: data.fullName, role: data.role },
      hasValidToken: hasValidToken,
      redirect: hasValidToken ? '/index.html' : '/activate.html'
    });
  } catch (err) {
    console.error("❌ Error during login:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Logout route
app.get("/api/logout", (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Protected route check
app.get("/api/check-auth", (req, res) => {
  if (req.session.isLoggedIn) {
    res.json({ isLoggedIn: true, user: req.session.user });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// ===============================
// TOKEN ENDPOINTS
// ===============================

// Generate token (for admin use)
app.post("/api/generate-token", async (req, res) => {
  try {
    const { plan, email } = req.body;
    
    if (!plan || !['week', 'month', 'lifetime'].includes(plan)) {
      return res.status(400).json({ success: false, message: "Invalid plan type" });
    }
    
    // Generate random 20-digit tokens for each plan type
    const weekToken = crypto.randomBytes(10).toString('hex'); // 10 bytes = 20 hex characters
    const monthToken = crypto.randomBytes(10).toString('hex');
    const lifetimeToken = crypto.randomBytes(10).toString('hex');
    
    // Calculate expiry date based on plan
    let expiresAt = null;
    if (plan !== 'lifetime') {
      expiresAt = new Date();
      if (plan === 'week') {
        expiresAt.setDate(expiresAt.getDate() + 7); // 1 week
      } else if (plan === 'month') {
        expiresAt.setDate(expiresAt.getDate() + 30); // 1 month
      }
    }
    
    // Store token in database (without user_id for now)
    const { data, error } = await supabase
      .from("tokens")
      .insert([{
        email: email || null,
        "1 week token": weekToken,
        "1 month token": monthToken,
        "lifetime token": lifetimeToken,
        valid: true,
        expires_at: expiresAt ? expiresAt.toISOString() : null
      }]);
    
    if (error) {
      console.error("Token generation error:", error);
      return res.status(500).json({ success: false, message: "Token generation failed" });
    }
    
    // Return the appropriate token based on the plan
    let activeToken;
    if (plan === 'week') activeToken = weekToken;
    else if (plan === 'month') activeToken = monthToken;
    else activeToken = lifetimeToken;
    
    res.json({ 
      success: true, 
      message: "Token generated successfully", 
      token: activeToken,
      plan: plan,
      expiresAt: expiresAt ? expiresAt.toISOString() : null
    });
  } catch (err) {
    console.error("❌ Error generating token:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Activate token
app.post("/api/activate-token", isAuthenticated, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.session.user.id;
    const userEmail = req.session.user.email;

    if (!token) {
      return res.status(400).json({ success: false, message: "Token is required" });
    }

    // Check if token exists and is valid in any of the token columns
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .or(`"1 week token".eq.${token},"1 month token".eq.${token},"lifetime token".eq.${token}`)
      .eq("valid", true)
      .is("user_id", null) // Token should not be assigned to any user yet
      .single();

    if (error || !data) {
      return res.status(400).json({ success: false, message: "Invalid or already used token" });
    }

    // Determine which type of token was used
    let plan = 'lifetime';
    if (data["1 week token"] === token) {
      plan = 'week';
    } else if (data["1 month token"] === token) {
      plan = 'month';
    }

    // Assign token to user and update email if not already set
    const { error: updateError } = await supabase
      .from("tokens")
      .update({ 
        user_id: userId,
        email: data.email || userEmail
      })
      .eq("id", data.id);

    if (updateError) {
      console.error("Token activation error:", updateError);
      return res.status(500).json({ success: false, message: "Token activation failed" });
    }

    res.json({ 
      success: true, 
      message: "Token activated successfully",
      plan: plan,
      expiresAt: data.expires_at
    });
  } catch (err) {
    console.error("❌ Error activating token:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Get user token info
app.get("/api/user/token", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    // Get user's active token
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", userId)
      .eq("valid", true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (error || !data || data.length === 0) {
      return res.json({ success: false, hasToken: false });
    }
    
    const token = data[0];
    
    // Check if token is expired
    if (token.expires_at && new Date(token.expires_at) < new Date()) {
      return res.json({ success: false, hasToken: false, expired: true });
    }
    
    // Determine which plan the user has
    let plan = 'lifetime';
    if (token["1 week token"] && !token["lifetime token"]) {
      plan = 'week';
    } else if (token["1 month token"] && !token["lifetime token"]) {
      plan = 'month';
    }
    
    res.json({ 
      success: true, 
      hasToken: true,
      plan: plan,
      expiresAt: token.expires_at,
      activatedAt: token.created_at,
      tokens: {
        weekToken: token["1 week token"],
        monthToken: token["1 month token"],
        lifetimeToken: token["lifetime token"]
      }
    });
  } catch (err) {
    console.error("❌ Error fetching token info:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===============================
// PROTECTED ROUTES
// ===============================

// Index page (requires token validation)
app.get("/", isAuthenticated, async (req, res, next) => {
  try {
    // Check if user has a valid token
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", req.session.user.id)
      .eq("valid", true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (error || !data || data.length === 0 || 
        (data[0].expires_at && new Date(data[0].expires_at) < new Date())) {
      return res.redirect('/activate.html');
    }
    
    next();
  } catch (err) {
    console.error("Token validation error:", err);
    res.redirect('/activate.html');
  }
}, (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

app.get("/index.html", isAuthenticated, async (req, res, next) => {
  try {
    // Check if user has a valid token
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", req.session.user.id)
      .eq("valid", true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (error || !data || data.length === 0 || 
        (data[0].expires_at && new Date(data[0].expires_at) < new Date())) {
      return res.redirect('/activate.html');
    }
    
    next();
  } catch (err) {
    console.error("Token validation error:", err);
    res.redirect('/activate.html');
  }
}, (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

// Protected bank routes
app.get("/palmpayform.html", isAuthenticated, hasValidToken, (req, res) => {
  res.sendFile(path.join(process.cwd(), "palmpayform.html"));
});

app.get("/opayform.html", isAuthenticated, hasValidToken, (req, res) => {
  res.sendFile(path.join(process.cwd(), "opayform.html"));
});

app.get("/receiptform.html", isAuthenticated, hasValidToken, (req, res) => {
  res.sendFile(path.join(process.cwd(), "receiptform.html"));
});

// ===============================
// START SERVER
// ===============================
const PORT = 3003; // Changed from 3002 to 3003
app.listen(PORT, async () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
