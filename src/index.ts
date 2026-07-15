import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { ObjectId } from "mongodb";
import { connectToDatabase } from "./db";
import { hashPassword, verifyPassword, signToken, verifyToken } from "./auth";
import Stripe from "stripe";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const stripe = new Stripe(
  process.env.STRIPE_SECRET_KEY || "temporary-mock-key-to-prevent-startup-error",
  { apiVersion: "2022-11-15" as any }
);

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing.
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());



// Multer memory storage configuration for file uploads
const upload = multer({ storage: multer.memoryStorage() });

app.get("/", (req, res) => {
  res.json({ message: "LushLeaves server is running" });
});

// 1. Image Upload Route (proxies multipart image upload to ImgBB)
app.post("/api/upload-image", upload.single("image"), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ success: false, message: "No image file provided." });
    }

    const apiKey = process.env.IMGBB_API_KEY || "d0c007137f61c3606f7b18991207131b";
    const base64Image = file.buffer.toString("base64");

    const imgbbForm = new FormData();
    imgbbForm.append("key", apiKey);
    imgbbForm.append("image", base64Image);

    const imgbbRes = await fetch("https://api.imgbb.com/1/upload", {
      method: "POST",
      body: imgbbForm,
    });

    const imgbbData = await imgbbRes.json() as any;

    if (!imgbbRes.ok || !imgbbData.success) {
      return res.status(502).json({
        success: false,
        message: imgbbData?.error?.message || "ImgBB upload failed.",
      });
    }

    return res.status(200).json({
      success: true,
      url: imgbbData.data.url,
    });
  } catch (err) {
    console.error("[upload-image] Server error:", err);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// 2. Auth Register Route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, role, imageUrl, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const { db } = await connectToDatabase();

    // Check if user already exists
    const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: "User with this email already exists." });
    }

    const userRole = role === "admin" ? "admin" : "user";
    const passwordHash = hashPassword(password);
    const now = new Date();

    const newUser = {
      name: name || "",
      email: email.toLowerCase(),
      passwordHash,
      role: userRole,
      imageUrl: imageUrl || "",
      createdAt: now,
    };

    const result = await db.collection("users").insertOne(newUser);
    const userId = result.insertedId.toString();

    // Generate JWT
    const token = signToken({
      userId,
      email: newUser.email,
      role: userRole,
    });

    return res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: userId,
        name: newUser.name,
        email: newUser.email,
        role: userRole,
        imageUrl: newUser.imageUrl,
      },
    });
  } catch (err: any) {
    console.error("Register Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 3. Auth Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const { db } = await connectToDatabase();

    const user = await db.collection("users").findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = verifyPassword(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = signToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    return res.status(200).json({
      message: "Logged in successfully",
      token,
      user: {
        id: user._id.toString(),
        name: user.name || "",
        email: user.email,
        role: user.role,
        imageUrl: user.imageUrl || "",
        createdAt: user.createdAt,
      },
    });
  } catch (err: any) {
    console.error("Login Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 3.5 Google Sign-in Verification Route (POST /api/auth/google)
app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ message: "Google credential token is required." });
    }

    // Instantiate Google OAuth client
    const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "99733512684-n5hudt7amkpacib5kgfs54vfbjd7dkdd.apps.googleusercontent.com";
    const googleClient = new OAuth2Client(clientId);

    // Verify Google ID Token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: clientId,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return res.status(400).json({ message: "Invalid Google ID token payload." });
    }

    const { email, name, picture } = payload;
    const { db } = await connectToDatabase();

    // Check if user already exists
    let user = await db.collection("users").findOne({ email: email.toLowerCase() });
    
    let userId: string;
    let userRole = "user";
    let userName = name || "";
    let userImageUrl = picture || "";

    if (!user) {
      // First time Google user: create account automatically
      const newUser = {
        name: userName,
        email: email.toLowerCase(),
        role: "user",
        imageUrl: userImageUrl,
        createdAt: new Date(),
        // No password hash since it's a social account
        passwordHash: "",
      };
      const result = await db.collection("users").insertOne(newUser);
      userId = result.insertedId.toString();
    } else {
      userId = user._id.toString();
      userRole = user.role || "user";
      // Update image or name if they were blank previously
      const updates: Record<string, string> = {};
      if (!user.name && userName) updates.name = userName;
      if (!user.imageUrl && userImageUrl) updates.imageUrl = userImageUrl;
      if (Object.keys(updates).length > 0) {
        await db.collection("users").updateOne({ _id: user._id }, { $set: updates });
      }
      userName = user.name || userName;
      userImageUrl = user.imageUrl || userImageUrl;
    }

    // Generate app JWT
    const token = signToken({
      userId,
      email: email.toLowerCase(),
      role: userRole as "user" | "admin",
    });

    return res.status(200).json({
      message: "Logged in with Google successfully",
      token,
      user: {
        id: userId,
        name: userName,
        email: email.toLowerCase(),
        role: userRole,
        imageUrl: userImageUrl,
      },
    });
  } catch (err: any) {
    console.error("Google Authentication Error:", err?.message || err);
    return res.status(500).json({ message: "Google authentication failed." });
  }
});

// 4. Get current user profile (GET /api/auth/me)
app.get("/api/auth/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    const { db } = await connectToDatabase();
    const user = await db.collection("users").findOne({ email: payload.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({
      id: user._id.toString(),
      name: user.name || "",
      email: user.email,
      role: user.role,
      imageUrl: user.imageUrl || "",
      createdAt: user.createdAt,
    });
  } catch (err: any) {
    console.error("Get Me Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 5. Update current user profile (PATCH /api/auth/me)
app.patch("/api/auth/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    const { name, imageUrl } = req.body;
    const updates: Record<string, string> = {};
    if (typeof name === "string") updates.name = name.trim();
    if (typeof imageUrl === "string") updates.imageUrl = imageUrl.trim();
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    let userId: ObjectId;
    try {
      userId = new ObjectId(payload.userId);
    } catch {
      return res.status(400).json({ message: "Invalid user ID in token" });
    }

    const { db } = await connectToDatabase();
    const result = await db.collection("users").findOneAndUpdate(
      { email: payload.email },
      { $set: updates },
      { returnDocument: "after" }
    );

    if (!result) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      id: result._id.toString(),
      name: result.name || "",
      email: result.email,
      role: result.role,
      imageUrl: result.imageUrl || "",
      createdAt: result.createdAt,
    });
  } catch (err: any) {
    console.error("[PATCH /api/auth/me] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 6. Get All Plants Route
app.get("/api/plants", async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const plants = await db.collection("plants").find({}).sort({ _id: -1 }).toArray();

    // Map _id to string id for the frontend
    const mappedPlants = plants.map((plant: any) => ({
      id: plant._id.toString(),
      title: plant.title,
      scientificName: plant.scientificName || "",
      category: plant.category || "Foliage",
      short: plant.short || "",
      description: plant.description || "",
      price: plant.price || 0,
      image: plant.image || "",
      difficulty: plant.difficulty || "Easy",
      watering: plant.watering || "",
      sunlight: plant.sunlight || "",
      temperature: plant.temperature || "",
      detailedCare: plant.detailedCare || [],
      commonProblems: plant.commonProblems || [],
    }));

    return res.status(200).json(mappedPlants);
  } catch (err: any) {
    console.error("Fetch Plants Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 7. Create a New Plant (Admin only)
app.post("/api/plants", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }
    const {
      title, scientificName, category, short, description,
      price, image, difficulty, watering, sunlight,
      temperature, detailedCare, commonProblems,
    } = req.body;
    if (!title || !price || !image) {
      return res.status(400).json({ message: "title, price, and image are required" });
    }
    const { db } = await connectToDatabase();
    const newPlant = {
      title: String(title).trim(),
      scientificName: String(scientificName || "").trim(),
      category: String(category || "Foliage").trim(),
      short: String(short || "").trim(),
      description: String(description || "").trim(),
      price: Number(price),
      image: String(image).trim(),
      difficulty: ["Easy", "Medium", "Hard"].includes(difficulty) ? difficulty : "Easy",
      watering: String(watering || "").trim(),
      sunlight: String(sunlight || "").trim(),
      temperature: String(temperature || "").trim(),
      detailedCare: Array.isArray(detailedCare) ? detailedCare : [],
      commonProblems: Array.isArray(commonProblems) ? commonProblems : [],
      createdAt: new Date(),
    };
    const result = await db.collection("plants").insertOne(newPlant);
    await logAdminAction(payload.email, `Created new plant: "${newPlant.title}" (${newPlant.category})`);
    return res.status(201).json({ message: "Plant created successfully", id: result.insertedId.toString() });
  } catch (err: any) {
    console.error("[POST /api/plants] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});
// 7.5. Update an Existing Plant (Admin only)
app.put("/api/plants/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }
    const { id } = req.params;
    let plantId: ObjectId;
    try {
      plantId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid plant ID" });
    }
    const {
      title, scientificName, category, short, description,
      price, image, difficulty, watering, sunlight,
      temperature, detailedCare, commonProblems,
    } = req.body;
    if (!title || !price || !image) {
      return res.status(400).json({ message: "title, price, and image are required" });
    }
    const { db } = await connectToDatabase();
    const updatedPlant = {
      title: String(title).trim(),
      scientificName: String(scientificName || "").trim(),
      category: String(category || "Foliage").trim(),
      short: String(short || "").trim(),
      description: String(description || "").trim(),
      price: Number(price),
      image: String(image).trim(),
      difficulty: ["Easy", "Medium", "Hard"].includes(difficulty) ? difficulty : "Easy",
      watering: String(watering || "").trim(),
      sunlight: String(sunlight || "").trim(),
      temperature: String(temperature || "").trim(),
      detailedCare: Array.isArray(detailedCare) ? detailedCare : [],
      commonProblems: Array.isArray(commonProblems) ? commonProblems : [],
    };
    const result = await db.collection("plants").updateOne(
      { _id: plantId },
      { $set: updatedPlant }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Plant not found" });
    }
    await logAdminAction(payload.email, `Updated plant: "${updatedPlant.title}" (${updatedPlant.category})`);
    return res.status(200).json({ message: "Plant updated successfully" });
  } catch (err: any) {
    console.error("[PUT /api/plants/:id] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 8. Delete a Plant (Admin only)
app.delete("/api/plants/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    let plantId: ObjectId;
    try {
      plantId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid plant ID" });
    }

    const { db } = await connectToDatabase();

    // Fetch plant details first to log its title
    const plant = await db.collection("plants").findOne({ _id: plantId });
    const plantTitle = plant ? plant.title : id;

    const result = await db.collection("plants").deleteOne({ _id: plantId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Plant not found" });
    }

    await logAdminAction(payload.email, `Deleted plant: "${plantTitle}" (ID: ${id})`);
    return res.status(200).json({ message: "Plant deleted successfully" });
  } catch (err: any) {
    console.error("[DELETE /api/plants/:id] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 9. Admin: Get all users
app.get("/api/users", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { db } = await connectToDatabase();
    const users = await db.collection("users").find({}).toArray();
    const mappedUsers = users.map((u: any) => ({
      id: u._id.toString(),
      name: u.name || "",
      email: u.email,
      role: u.role,
      imageUrl: u.imageUrl || "",
      createdAt: u.createdAt,
    }));

    return res.status(200).json(mappedUsers);
  } catch (err: any) {
    console.error("[GET /api/users] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 10. Admin: Change User Role
app.patch("/api/users/:id/role", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    const { role } = req.body;
    if (!["user", "admin"].includes(role)) {
      return res.status(400).json({ message: "Invalid role value" });
    }

    let userId: ObjectId;
    try {
      userId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const { db } = await connectToDatabase();

    // Fetch user details first to log their email
    const userToEdit = await db.collection("users").findOne({ _id: userId });
    const userEmail = userToEdit ? userToEdit.email : id;

    const result = await db.collection("users").updateOne(
      { _id: userId },
      { $set: { role } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    await logAdminAction(payload.email, `Updated user role of "${userEmail}" to "${role}"`);
    return res.status(200).json({ message: "User role updated successfully" });
  } catch (err: any) {
    console.error("[PATCH /api/users/:id/role] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 11. Admin: Delete User
app.delete("/api/users/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    let userId: ObjectId;
    try {
      userId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const { db } = await connectToDatabase();

    // Fetch user details first to log email
    const userToDelete = await db.collection("users").findOne({ _id: userId });
    const userEmail = userToDelete ? userToDelete.email : id;

    const result = await db.collection("users").deleteOne({ _id: userId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    await logAdminAction(payload.email, `Deleted user account: "${userEmail}" (ID: ${id})`);
    return res.status(200).json({ message: "User deleted successfully" });
  } catch (err: any) {
    console.error("[DELETE /api/users/:id] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 12. Submit Contact Message
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ message: "Name, email, and message are required" });
    }

    const { db } = await connectToDatabase();
    const newMessage = {
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      subject: String(subject || "General Inquiry").trim(),
      message: String(message).trim(),
      createdAt: new Date(),
      status: "unread",
    };

    await db.collection("contacts").insertOne(newMessage);
    return res.status(201).json({ message: "Message submitted successfully" });
  } catch (err: any) {
    console.error("[POST /api/contact] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 13. Admin: Get all contact messages
app.get("/api/contact", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { db } = await connectToDatabase();
    const contacts = await db.collection("contacts").find({}).sort({ createdAt: -1 }).toArray();
    const mapped = contacts.map((c: any) => ({
      id: c._id.toString(),
      name: c.name,
      email: c.email,
      subject: c.subject,
      message: c.message,
      createdAt: c.createdAt,
      status: c.status || "unread",
    }));

    return res.status(200).json(mapped);
  } catch (err: any) {
    console.error("[GET /api/contact] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 14. Admin: Delete contact message
app.delete("/api/contact/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    let contactId: ObjectId;
    try {
      contactId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid message ID" });
    }

    const { db } = await connectToDatabase();
    const result = await db.collection("contacts").deleteOne({ _id: contactId });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Message not found" });
    }

    return res.status(200).json({ message: "Message deleted successfully" });
  } catch (err: any) {
    console.error("[DELETE /api/contact/:id] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 15. Admin: Get Activity Logs (Audit Trail)
app.get("/api/admin/logs", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { db } = await connectToDatabase();
    const logs = await db.collection("logs").find({}).sort({ timestamp: -1 }).limit(100).toArray();
    return res.status(200).json(logs);
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Helper to log administrative actions
async function logAdminAction(email: string, action: string) {
  try {
    const { db } = await connectToDatabase();
    await db.collection("logs").insertOne({
      admin: email,
      action,
      timestamp: new Date(),
    });
  } catch (e) {
    console.error("Failed to log admin action:", e);
  }
}

// 15.9 User: Validate Coupon Code publicly
app.get("/api/promo/validate", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) {
      return res.status(400).json({ message: "Code parameter is required" });
    }

    const { db } = await connectToDatabase();
    const coupon = await db.collection("coupons").findOne({
      code: String(code).toUpperCase(),
      isActive: true
    });

    if (!coupon) {
      return res.status(404).json({ message: "Invalid or inactive promo code" });
    }

    return res.status(200).json({ code: coupon.code, discount: coupon.discount });
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 16. Admin: Get and Create Promo Codes (Coupons)
app.get("/api/admin/coupons", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { db } = await connectToDatabase();
    const coupons = await db.collection("coupons").find({}).sort({ createdAt: -1 }).toArray();
    return res.status(200).json(coupons);
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/admin/coupons", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { code, discount, isActive } = req.body;
    if (!code || typeof discount !== "number") {
      return res.status(400).json({ message: "code and discount are required" });
    }

    const { db } = await connectToDatabase();
    const newCoupon = {
      code: String(code).trim().toUpperCase(),
      discount: Number(discount),
      isActive: Boolean(isActive),
      createdAt: new Date(),
    };

    await db.collection("coupons").insertOne(newCoupon);
    await logAdminAction(payload.email, `created promo code: ${newCoupon.code} ($${newCoupon.discount.toFixed(2)} off)`);
    return res.status(201).json({ message: "Promo code created successfully" });
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 16.2 Admin: Delete Promo Code (Coupon)
app.delete("/api/admin/coupons/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    let couponId: ObjectId;
    try {
      couponId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid coupon ID" });
    }

    const { db } = await connectToDatabase();

    // Fetch coupon details first to log its name & discount
    const coupon = await db.collection("coupons").findOne({ _id: couponId });
    const couponCode = coupon ? coupon.code : id;
    const couponDiscount = coupon ? `$${coupon.discount.toFixed(2)} off` : "";

    const result = await db.collection("coupons").deleteOne({ _id: couponId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Promo code not found" });
    }

    await logAdminAction(payload.email, `deleted promo code: ${couponCode} ${couponDiscount ? `(${couponDiscount})` : ""}`);
    return res.status(200).json({ message: "Promo code deleted successfully" });
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 16.9 User: Submit New Checkout Order
app.post("/api/orders", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { items, total, shippingCharge, appliedPromo, discount } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0 || typeof total === "undefined") {
      return res.status(400).json({ message: "Invalid checkout request body" });
    }

    const { db } = await connectToDatabase();
    const newOrder = {
      userId: payload.userId,
      userEmail: payload.email,
      items: items.map((item: any) => ({
        plantId: item.plantId,
        title: item.title,
        quantity: Number(item.quantity),
        price: Number(item.price)
      })),
      total: Number(total),
      shippingCharge: typeof shippingCharge !== "undefined" ? Number(shippingCharge) : 15,
      appliedPromo: appliedPromo || null,
      discount: typeof discount !== "undefined" ? Number(discount) : 0,
      status: "Pending",
      createdAt: new Date()
    };

    const result = await db.collection("orders").insertOne(newOrder);
    return res.status(201).json({ message: "Order placed successfully", orderId: result.insertedId.toString() });
  } catch (err: any) {
    console.error("[POST /api/orders] Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 16.9.5 Stripe: Create Payment Checkout Session
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { items, shippingCharge, appliedPromo, discount, origin } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "Invalid checkout items list" });
    }

    // Construct line items list
    const lineItems = items.map((item: any) => ({
      price_data: {
        currency: "usd",
        product_data: {
          name: item.title,
          images: item.image ? [item.image] : [],
        },
        unit_amount: Math.round(Number(item.price) * 100),
      },
      quantity: Number(item.quantity),
    }));

    // If shipping charge is present, add it as a line item
    const shipFee = typeof shippingCharge !== "undefined" ? Number(shippingCharge) : 15;
    if (shipFee > 0) {
      lineItems.push({
        price_data: {
          currency: "usd",
          product_data: {
            name: "Standard Shipping & Handling",
            images: [],
          },
          unit_amount: Math.round(shipFee * 100),
        },
        quantity: 1,
      });
    }

    // If discount coupon is present, apply it as a negative unit item
    const discountVal = Number(discount || 0);
    if (discountVal > 0) {
      lineItems.push({
        price_data: {
          currency: "usd",
          product_data: {
            name: `Coupon Code: ${appliedPromo || "DISCOUNT"}`,
            images: [],
          },
          unit_amount: -Math.round(discountVal * 100),
        },
        quantity: 1,
      });
    }

    const appOrigin = origin || "http://localhost:3000";

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: lineItems,
      mode: "payment",
      success_url: `${appOrigin}/success?session_id={CHECKOUT_SESSION_ID}&shippingCharge=${shipFee}&appliedPromo=${appliedPromo || ""}&discount=${discountVal}`,
      cancel_url: `${appOrigin}/cart`,
      metadata: {
        userId: payload.userId,
        userEmail: payload.email,
        itemsJson: JSON.stringify(items.map((it: any) => ({
          plantId: it.plantId,
          title: it.title,
          quantity: it.quantity,
          price: it.price
        }))),
        shippingCharge: String(shipFee),
        appliedPromo: appliedPromo || "",
        discount: String(discountVal),
      },
    });

    return res.status(200).json({ url: session.url, sessionId: session.id });
  } catch (err: any) {
    console.error("[POST /api/create-checkout-session] Error:", err);
    return res.status(500).json({ message: err.message || "Internal server error" });
  }
});

// 16.9.6 Stripe: Retrieve Completed Checkout Session Details
app.get("/api/checkout-session/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const session = await stripe.checkout.sessions.retrieve(id);
    return res.status(200).json(session);
  } catch (err: any) {
    return res.status(500).json({ message: err.message || "Internal server error" });
  }
});

// 16.10 User: Get Personal Order History & Metrics
app.get("/api/orders/my-orders", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { db } = await connectToDatabase();
    const myOrders = await db.collection("orders").find({ userEmail: payload.email }).sort({ createdAt: -1 }).toArray();
    return res.status(200).json(myOrders);
  } catch (err: any) {
    console.error("[GET /api/orders/my-orders] Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 17. Admin: Get and Update Order Fulfillments
app.get("/api/admin/orders", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { db } = await connectToDatabase();
    const orders = await db.collection("orders").find({}).sort({ createdAt: -1 }).toArray();
    return res.status(200).json(orders);
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.patch("/api/admin/orders/:id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const { id } = req.params;
    const { status } = req.body;
    if (!["Pending", "Processing", "Shipped", "Delivered"].includes(status)) {
      return res.status(400).json({ message: "Invalid order status value" });
    }

    const { db } = await connectToDatabase();
    const result = await db.collection("orders").updateOne(
      { _id: new ObjectId(id) },
      { $set: { status } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    await logAdminAction(payload.email, `Updated order status of ${id} to ${status}`);
    return res.status(200).json({ message: "Order status updated successfully" });
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Background worker to automatically turn off expired promos & log them
async function checkExpiredPromos() {
  try {
    const { db } = await connectToDatabase();
    const configDoc = await db.collection("config").findOne({ key: "system_features" });
    if (!configDoc) return;

    const current = configDoc.value;
    const now = new Date().getTime();
    let changed = false;
    const expiredLogs: string[] = [];

    // Check Free Shipping Promo Expiry
    if (current.freeShippingPromo && current.freeShippingExpiry && now > new Date(current.freeShippingExpiry).getTime()) {
      current.freeShippingPromo = false;
      current.freeShippingExpiry = null;
      changed = true;
      expiredLogs.push("system turned off free shipping promo");
    }

    // Check Seasonal Banner Expiry
    if (current.seasonalBanner && current.seasonalBannerExpiry && now > new Date(current.seasonalBannerExpiry).getTime()) {
      current.seasonalBanner = false;
      current.seasonalBannerExpiry = null;
      changed = true;
      expiredLogs.push("system turned off seasonal banner");
    }

    if (changed) {
      await db.collection("config").updateOne(
        { key: "system_features" },
        { $set: { value: current } }
      );

      // Log as system actions
      for (const logText of expiredLogs) {
        await db.collection("logs").insertOne({
          admin: "system",
          action: logText,
          timestamp: new Date(),
        });
      }
      console.log(`[system] Auto-deactivated expired flags: ${expiredLogs.join(", ")}`);
    }
  } catch (err) {
    console.error("Error checking expired promo tags:", err);
  }
}

// Check every 10 seconds
setInterval(checkExpiredPromos, 10000);

// 18. Admin: Get and Update System Feature Flags
app.get("/api/admin/config", async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const config = await db.collection("config").findOne({ key: "system_features" });
    if (!config) {
      return res.status(200).json({
        maintenanceMode: false,
        checkoutEnabled: true,
        freeShippingPromo: false,
        freeShippingExpiry: null,
        seasonalBanner: false,
        seasonalBannerExpiry: null,
        emailNotifications: true,
        shippingCharge: 15
      });
    }
    const val = config.value;
    if (typeof val.shippingCharge === "undefined") {
      val.shippingCharge = 15;
    }
    return res.status(200).json(val);
  } catch (err: any) {
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/admin/config", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }

    const {
      maintenanceMode,
      checkoutEnabled,
      freeShippingPromo,
      freeShippingExpiry,
      seasonalBanner,
      seasonalBannerExpiry,
      emailNotifications,
      shippingCharge
    } = req.body;

    const { db } = await connectToDatabase();

    // Fetch current settings to identify changes
    const configDoc = await db.collection("config").findOne({ key: "system_features" });
    const currentVal = configDoc ? configDoc.value : {
      maintenanceMode: false,
      checkoutEnabled: true,
      freeShippingPromo: false,
      freeShippingExpiry: null,
      seasonalBanner: false,
      seasonalBannerExpiry: null,
      emailNotifications: true,
      shippingCharge: 15
    };

    const nextVal = {
      maintenanceMode: Boolean(maintenanceMode),
      checkoutEnabled: Boolean(checkoutEnabled),
      freeShippingPromo: Boolean(freeShippingPromo),
      freeShippingExpiry: freeShippingExpiry ? new Date(freeShippingExpiry).toISOString() : null,
      seasonalBanner: Boolean(seasonalBanner),
      seasonalBannerExpiry: seasonalBannerExpiry ? new Date(seasonalBannerExpiry).toISOString() : null,
      emailNotifications: Boolean(emailNotifications),
      shippingCharge: typeof shippingCharge !== "undefined" ? Number(shippingCharge) : 15
    };

    await db.collection("config").updateOne(
      { key: "system_features" },
      { $set: { value: nextVal } },
      { upsert: true }
    );

    // Build user-friendly change log string
    const changes: string[] = [];
    if (currentVal.maintenanceMode !== nextVal.maintenanceMode) {
      changes.push(`turned ${nextVal.maintenanceMode ? "on" : "off"} maintenance mode`);
    }
    if (currentVal.checkoutEnabled !== nextVal.checkoutEnabled) {
      changes.push(`turned ${nextVal.checkoutEnabled ? "on" : "off"} checkout features`);
    }
    if (currentVal.freeShippingPromo !== nextVal.freeShippingPromo) {
      changes.push(`turned ${nextVal.freeShippingPromo ? "on" : "off"} free shipping promo`);
    }
    if (currentVal.seasonalBanner !== nextVal.seasonalBanner) {
      changes.push(`turned ${nextVal.seasonalBanner ? "on" : "off"} seasonal banner`);
    }
    if (currentVal.emailNotifications !== nextVal.emailNotifications) {
      changes.push(`turned ${nextVal.emailNotifications ? "on" : "off"} email notifications`);
    }
    if (Number(currentVal.shippingCharge) !== Number(nextVal.shippingCharge)) {
      changes.push(`updated shipping charge to $${Number(nextVal.shippingCharge).toFixed(2)}`);
    }

    if (changes.length > 0) {
      const actionText = changes.join(" and ");
      await logAdminAction(payload.email, actionText);
    }

    return res.status(200).json({ message: "System configuration updated successfully" });
  } catch (err: any) {
    console.error("[POST /api/admin/config] Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Start Express server
app.listen(PORT, () => {
  console.log(`[server] LushLeaves server is running on http://localhost:${PORT}`);
});

export default app;

