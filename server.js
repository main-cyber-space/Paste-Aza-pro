// server.js
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// 🔹 Replace these with your Supabase project settings
const SUPABASE_URL = "https://YOUR_PROJECT.supabase.co";
const SUPABASE_KEY = "YOUR_SERVICE_ROLE_KEY"; // use service_role, NOT anon
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ===============================
// USER ENDPOINT: Validate Token
// ===============================
app.post("/validate-token", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ success: false, message: "Token is required" });
    }

    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("token", token)
      .eq("valid", true)
      .single();

    if (error || !data) {
      return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }

    return res.json({ success: true, token: data });
  } catch (err) {
    console.error("❌ Error validating token:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===============================
// ADMIN ENDPOINT: View all tokens
// ===============================
app.get("/admin/tokens", async (req, res) => {
  try {
    const { password } = req.query;
    if (password !== "admin123") {
      return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    const { data, error } = await supabase.from("tokens").select("*");
    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("❌ Error fetching tokens:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===============================
// START SERVER
// ===============================
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
