const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { OpenAI } = require("openai");
const auth = require("./auth");
const multer = require("multer");
const path = require("path");const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { OpenAI } = require("openai");
const auth = require("./auth");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();
const { RtcTokenBuilder, RtcRole } = require("agora-token");

const app = express();

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/jpg",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only PDF, DOC, DOCX, and image files are allowed."
        ),
        false
      );
    }
  },
});

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() =>
    console.log("MongoDB Connected Successfully to ehealth_data database")
  )
  .catch((err) => console.log("MongoDB Connection Error:", err));

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  doctorName: { type: String, required: true },
  doctorId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  specialty: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Doctor = mongoose.model("Doctor", doctorSchema);

// Patient Schema
const patientSchema = new mongoose.Schema({
  patientName: { type: String, required: true },
  patientId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  contact: { type: String },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Patient = mongoose.model("Patient", patientSchema);

// Pharmacy Schema
const pharmacySchema = new mongoose.Schema({
  pharmacyName: { type: String, required: true },
  pharmacyId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  address: { type: String, required: true },
  contact: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Pharmacy = mongoose.model("Pharmacy", pharmacySchema);

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  specialty: { type: String, required: true },
  doctor: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  reason: { type: String, required: true },
  phone: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "confirmed", "rescheduled", "cancelled"],
    default: "pending",
  },
  callStatus: {
    type: String,
    enum: ["none", "started"],
    default: "none",
  },
  createdAt: { type: Date, default: Date.now },
});

const Appointment = mongoose.model("Appointment", appointmentSchema);

// Prescription Schema
const prescriptionSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  doctorId: { type: String, required: true },
  patientId: { type: String, required: true },
  description: { type: String, required: true },
  files: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "File",
    },
  ],
  deliveryStatus: {
    type: String,
    enum: ["pending", "sent", "rejected", "delivered"],
    default: "pending",
  },
  deliveryDetails: {
    name: String,
    phone: String,
    address: String,
    city: String,
    pharmacy: String,
  },
  createdAt: { type: Date, default: Date.now },
});

const Prescription = mongoose.model("Prescription", prescriptionSchema);

// File Schema for prescription attachments
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  path: { type: String, required: true },
  url: { type: String, required: true },
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  uploadedBy: { type: String, required: true }, // doctorId
  createdAt: { type: Date, default: Date.now },
});

const File = mongoose.model("File", fileSchema);

// Sensor Data Schema
const sensorDataSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  ecg: { type: String },
  bloodPressure: {
    systolic: { type: Number },
    diastolic: { type: Number },
  },
  oxygenSaturation: { type: Number },
  respirationRate: { type: Number },
  temperature: { type: Number },
  timestamp: { type: Date, default: Date.now },
});

const SensorData = mongoose.model("SensorData", sensorDataSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  sender: {
    type: String,
    enum: ["doctor", "patient"],
    required: true,
  },
  text: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const Message = mongoose.model("Message", messageSchema);

// Doctor Registration Route
app.post("/doctors/register", async (req, res) => {
  try {
    const { doctorName, doctorId, email, password, specialty } = req.body;

    // Check if doctor already exists
    const existingDoctor = await Doctor.findOne({
      $or: [{ email }, { doctorId }],
    });

    if (existingDoctor) {
      return res.status(400).json({
        message: "Doctor with this email or ID already exists",
      });
    }

    // Create new doctor
    const doctor = new Doctor({
      doctorName,
      doctorId,
      email,
      password, // Note: In production, you should hash the password
      specialty,
    });

    await doctor.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Doctor registered successfully",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering doctor",
    });
  }
});

// Patient Registration Route
app.post("/patients/register", async (req, res) => {
  try {
    const { patientName, patientId, email, contact, password } = req.body;

    // Check if patient already exists
    const existingPatient = await Patient.findOne({
      $or: [{ email }, { patientId }],
    });

    if (existingPatient) {
      return res.status(400).json({
        message: "Patient with this email or ID already exists",
      });
    }

    // Create new patient
    const patient = new Patient({
      patientName,
      patientId,
      email,
      contact,
      password,
    });

    await patient.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Patient registered successfully",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering patient",
    });
  }
});

// Doctor Login Route
app.post("/doctors/login", async (req, res) => {
  try {
    const { doctorId, password } = req.body;

    // Find doctor by doctorId
    const doctor = await Doctor.findOne({ doctorId });

    if (!doctor) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Check password (Note: In production, use proper password comparison with hashed passwords)
    if (doctor.password !== password) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Doctor Profile Route
app.get("/doctors/profile", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    res.json({
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Patient Login Route
app.post("/patients/login", async (req, res) => {
  try {
    const { patientId, password } = req.body;

    // Find patient by patientId
    const patient = await Patient.findOne({ patientId });

    if (!patient) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Check password
    if (patient.password !== password) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Patient Profile Route
app.get("/patients/profile", auth, async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }
    res.json(patient);
  } catch (error) {
    console.error("Error fetching patient profile:", error);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// Update Patient Profile Route
app.put("/patients/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, contact, password } = req.body;

    // Find the patient by ID from the auth token
    const patient = await Patient.findById(req.user.id);

    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }

    // Check if email is being changed and if it's already taken
    if (email && email !== patient.email) {
      const existingPatient = await Patient.findOne({ email });
      if (existingPatient) {
        return res.status(400).json({ message: "Email already in use" });
      }
    }

    // Update patient information
    patient.patientName = name || patient.patientName;
    patient.email = email || patient.email;
    patient.contact = contact || patient.contact;

    // Only update password if a new one is provided
    if (password) {
      patient.password = password; // Note: In production, hash the password
    }

    await patient.save();

    res.json({
      message: "Profile updated successfully",
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

// Pharmacy Registration Route
app.post("/pharmacies/register", async (req, res) => {
  try {
    const { pharmacyName, pharmacyId, email, address, contact, password } =
      req.body;

    // Check if pharmacy already exists
    const existingPharmacy = await Pharmacy.findOne({
      $or: [{ email }, { pharmacyId }],
    });

    if (existingPharmacy) {
      return res.status(400).json({
        message: "Pharmacy with this email or ID already exists",
      });
    }

    // Create new pharmacy
    const pharmacy = new Pharmacy({
      pharmacyName,
      pharmacyId,
      email,
      address,
      contact,
      password,
    });

    await pharmacy.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Pharmacy registered successfully",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering pharmacy",
    });
  }
});

// Pharmacy Login Route
app.post("/pharmacies/login", async (req, res) => {
  try {
    const { pharmacyId, password } = req.body;

    // Find pharmacy by pharmacyId
    const pharmacy = await Pharmacy.findOne({ pharmacyId });

    if (!pharmacy) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Check password
    if (pharmacy.password !== password) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Protected Pharmacy Routes
app.get("/pharmacies/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({ message: "Pharmacy not found" });
    }
    res.json(pharmacy);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacy profile" });
  }
});

// ChatGPT Endpoint
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body;

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content:
            "You are a helpful medical assistant chatbot. Provide accurate and helpful information about health-related topics. Always remind users to consult healthcare professionals for medical advice.",
        },
        {
          role: "user",
          content: message,
        },
      ],
      max_tokens: 150,
    });

    res.json({
      reply: completion.choices[0].message.content,
    });
  } catch (error) {
    console.error("ChatGPT API Error:", error);
    res.status(500).json({
      message: "Error processing your request",
    });
  }
});

// Doctor Profile Update Route
app.put("/doctors/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const doctorId = req.user.id;

    // Find doctor by ID
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Update fields
    if (name) doctor.doctorName = name;
    if (email) doctor.email = email;
    if (password) doctor.password = password; // Note: In production, hash the password

    await doctor.save();

    res.json({
      message: "Profile updated successfully",
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Get Pharmacy Profile Route
app.get("/pharmacy/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    res.json({
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Update Pharmacy Profile Route
app.put("/pharmacy/profileupdate", auth, async (req, res) => {
  try {
    const { pharmacyName, email, address, contact, password } = req.body;
    const pharmacyId = req.user.id;

    // Find pharmacy by ID
    const pharmacy = await Pharmacy.findById(pharmacyId);
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    // Update fields
    if (pharmacyName) pharmacy.pharmacyName = pharmacyName;
    if (email) pharmacy.email = email;
    if (address) pharmacy.address = address;
    if (contact) pharmacy.contact = contact;
    if (password) pharmacy.password = password; // Note: In production, hash the password

    await pharmacy.save();

    res.json({
      message: "Profile updated successfully",
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Appointment Routes
// Get all appointments for a patient
app.get("/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({ date: -1, time: -1 });
    res.json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Create new appointment
app.post("/appointments", auth, async (req, res) => {
  try {
    const { patientId, specialty, doctor, date, time, reason, phone } =
      req.body;

    const appointment = new Appointment({
      patientId,
      specialty,
      doctor,
      date,
      time,
      reason,
      phone,
    });

    await appointment.save();
    res.status(201).json({
      message: "Appointment created successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error creating appointment:", error);
    res.status(500).json({ message: "Error creating appointment" });
  }
});

// Delete appointment
app.delete("/appointments/:id", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findByIdAndDelete(req.params.id);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({ message: "Appointment deleted successfully" });
  } catch (error) {
    console.error("Error deleting appointment:", error);
    res.status(500).json({ message: "Error deleting appointment" });
  }
});

// Update appointment status
app.patch("/appointments/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const appointment = await Appointment.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({
      message: "Appointment status updated successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error updating appointment status:", error);
    res.status(500).json({ message: "Error updating appointment status" });
  }
});

// Get all doctors grouped by specialty
app.get("/doctors", async (req, res) => {
  try {
    const doctors = await Doctor.find({}, "doctorName specialty");
    const doctorsBySpecialty = doctors.reduce((acc, doctor) => {
      if (!acc[doctor.specialty]) {
        acc[doctor.specialty] = [];
      }
      acc[doctor.specialty].push(doctor.doctorName);
      return acc;
    }, {});
    res.json(doctorsBySpecialty);
  } catch (error) {
    console.error("Error fetching doctors:", error);
    res.status(500).json({ message: "Error fetching doctors" });
  }
});

// Get Doctor's Appointments
app.get("/doctors/appointments", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const appointments = await Appointment.find({
      doctor: doctor.doctorName,
    }).sort({
      date: -1,
      time: -1,
    });

    res.status(200).json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Accept Appointment
app.put("/doctors/appointments/:id/accept", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "confirmed";
    await appointment.save();

    res.status(200).json({ message: "Appointment accepted", appointment });
  } catch (error) {
    console.error("Error accepting appointment:", error);
    res.status(500).json({ message: "Error accepting appointment" });
  }
});

// Reschedule Appointment
app.put("/doctors/appointments/:id/reschedule", auth, async (req, res) => {
  try {
    const { date, time, note } = req.body;
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }
    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.date = date;
    appointment.time = time;
    appointment.note = note;
    appointment.status = "rescheduled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rescheduled", appointment });
  } catch (error) {
    console.error("Error rescheduling appointment:", error);
    res.status(500).json({ message: "Error rescheduling appointment" });
  }
});

// Reject Appointment
app.put("/doctors/appointments/:id/reject", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "cancelled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rejected", appointment });
  } catch (error) {
    console.error("Error rejecting appointment:", error);
    res.status(500).json({ message: "Error rejecting appointment" });
  }
});

// Upload Prescription
app.post("/prescriptions", auth, async (req, res) => {
  try {
    const { appointmentId, description, files } = req.body;

    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const prescription = new Prescription({
      appointmentId,
      doctorId: doctor.doctorId,
      patientId: appointment.patientId,
      description,
      files: files || [],
    });

    await prescription.save();
    res.status(201).json(prescription);
  } catch (error) {
    console.error("Error uploading prescription:", error);
    res.status(500).json({ message: "Error uploading prescription" });
  }
});

// Upload file for prescription
app.post(
  "/prescriptions/upload-file",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { appointmentId } = req.body;

      // Verify appointment exists
      const appointment = await Appointment.findById(appointmentId);
      if (!appointment) {
        return res.status(404).json({ message: "Appointment not found" });
      }

      const doctor = await Doctor.findById(req.user.id).select("-password");
      if (!doctor) {
        return res.status(404).json({
          message: "Doctor not found",
        });
      }

      // Create file record
      const file = new File({
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path,
        url: `${req.protocol}://${req.get("host")}/uploads/${
          req.file.filename
        }`,
        appointmentId: appointmentId,
        uploadedBy: doctor.doctorId,
      });

      await file.save();
      res.status(201).json(file);
    } catch (error) {
      console.error("Error uploading file:", error);
      res.status(500).json({ message: "Error uploading file" });
    }
  }
);

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res
        .status(400)
        .json({ message: "File too large. Maximum size is 10MB." });
    }
    return res.status(400).json({ message: error.message });
  }

  if (error.message.includes("Invalid file type")) {
    return res.status(400).json({ message: error.message });
  }

  next(error);
});

// Get files for an appointment
app.get("/prescriptions/:appointmentId/files", auth, async (req, res) => {
  try {
    const files = await File.find({
      appointmentId: req.params.appointmentId,
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching files:", error);
    res.status(500).json({ message: "Error fetching files" });
  }
});

// Delete file
app.delete("/prescriptions/file/:fileId", auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Check if doctor owns the file
    if (file.uploadedBy !== doctor.doctorId) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this file" });
    }

    // Delete physical file
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    // Delete file record
    await File.findByIdAndDelete(req.params.fileId);

    // Remove file reference from prescription
    await Prescription.updateMany(
      { files: req.params.fileId },
      { $pull: { files: req.params.fileId } }
    );

    res.json({ message: "File deleted successfully" });
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).json({ message: "Error deleting file" });
  }
});

// Get Patient's Sensor Data
app.get("/sensor-data/:patientId", auth, async (req, res) => {
  try {
    const sensorData = await SensorData.find({
      patientId: req.params.patientId,
    })
      .sort({ timestamp: -1 })
      .limit(1);

    if (!sensorData.length) {
      return res.status(404).json({ message: "No sensor data found" });
    }

    res.json(sensorData[0]);
  } catch (error) {
    console.error("Error fetching sensor data:", error);
    res.status(500).json({ message: "Error fetching sensor data" });
  }
});

// Update Sensor Data
app.post("/sensor-data", auth, async (req, res) => {
  try {
    const {
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    } = req.body;

    const sensorData = new SensorData({
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    });

    await sensorData.save();
    res.status(201).json(sensorData);
  } catch (error) {
    console.error("Error updating sensor data:", error);
    res.status(500).json({ message: "Error updating sensor data" });
  }
});

// Get Prescription for Appointment
app.get("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    }).populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "No prescription found" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription:", error);
    res.status(500).json({ message: "Error fetching prescription" });
  }
});

// Get Patient Appointments
app.get("/patient/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({
      date: -1,
      time: -1,
    });
    const appointmentsWithPrescriptions = await Promise.all(
      appointments.map(async (appointment) => {
        const prescription = await Prescription.findOne({
          appointmentId: appointment._id,
        });
        return {
          ...appointment.toObject(),
          prescription: prescription ? prescription.description : null,
          deliveryStatus: prescription ? prescription.deliveryStatus : null,
          prescriptionId: prescription ? prescription._id : null,
        };
      })
    );
    res.json(appointmentsWithPrescriptions);
  } catch (error) {
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Update Prescription Delivery Status
app.post("/prescription/delivery/:prescriptionId", auth, async (req, res) => {
  try {
    const { name, phone, address, city, pharmacy } = req.body;
    const prescription = await Prescription.findById(req.params.prescriptionId);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    prescription.deliveryStatus = "sent";
    prescription.deliveryDetails = {
      name,
      phone,
      address,
      city,
      pharmacy,
    };

    await prescription.save();
    res.json({ message: "Delivery status updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating delivery status" });
  }
});

// Get Video Call Token
app.post("/video-call/token", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    // Set callStatus to 'started' when doctor or patient initiates the call
    if (req.user.role === "doctor" || req.user.role === "patient") {
      appointment.callStatus = "started";
      await appointment.save();
    }

    // Generate a unique channel name for the video call
    const channelName = `appointment-${appointmentId}`;

    // Generate Agora token
    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERTIFICATE;
    const uid = 0; // Set to 0 to let Agora assign a uid
    const role = RtcRole.PUBLISHER; // Use RtcRole enum
    const privilegeExpiredTs = 3600; // Token valid for 1 hour

    const token = RtcTokenBuilder.buildTokenWithUid(
      appID,
      appCertificate,
      channelName,
      uid,
      role,
      privilegeExpiredTs
    );

    // Generate a JWT token for authentication
    const jwtToken = jwt.sign(
      {
        appointmentId,
        patientId: appointment.patientId,
        doctorId: appointment.doctorId,
        role: req.user.role,
        channelName,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token: jwtToken,
      agoraToken: token,
      channelName,
      appID: process.env.AGORA_APP_ID,
    });
  } catch (error) {
    console.error("Error generating video call token:", error);
    res.status(500).json({ message: "Error generating video call token" });
  }
});

// Get Pharmacies by City
app.get("/pharmacies/:address", async (req, res) => {
  try {
    const { address } = req.params;
    const pharmacies = await Pharmacy.find({ address: address });
    res.json(pharmacies);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacies" });
  }
});

// Get All Cities with Pharmacies
app.get("/pharmacy-address", async (req, res) => {
  try {
    const address = await Pharmacy.distinct("address");

    res.json(address);
  } catch (error) {
    res.status(500).json({ message: "Error fetching cities" });
  }
});

// Update Prescription
app.put("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const { description, files } = req.body;
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    });

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (prescription.doctorId !== doctor.doctorId) {
      return res.status(403).json({
        message: "Not authorized to modify this prescription",
      });
    }

    prescription.description = description;
    if (files) {
      prescription.files = files;
    }
    await prescription.save();
    res.json(prescription);
  } catch (error) {
    console.error("Error updating prescription:", error);
    res.status(500).json({ message: "Error updating prescription" });
  }
});

// Get chat messages for an appointment
app.get("/messages/:appointmentId", auth, async (req, res) => {
  try {
    const { appointmentId } = req.params;
    const messages = await Message.find({ appointmentId })
      .sort({ timestamp: 1 })
      .limit(50);
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Error fetching messages" });
  }
});

// Send a new message
app.post("/messages", auth, async (req, res) => {
  try {
    const { appointmentId, text } = req.body;
    const sender = req.user.role === "doctor" ? "doctor" : "patient";

    const message = new Message({
      appointmentId,
      sender,
      text,
    });

    await message.save();
    res.status(201).json(message);
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Error sending message" });
  }
});

// Get all prescriptions for a pharmacy
app.get("/pharmacy/prescriptions", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    const prescriptions = await Prescription.find({
      "deliveryDetails.pharmacy": pharmacy.pharmacyId,
    })
      .populate("appointmentId")
      .populate("files")
      .sort({ createdAt: -1 });

    res.json(prescriptions);
  } catch (error) {
    console.error("Error fetching prescriptions:", error);
    res.status(500).json({ message: "Error fetching prescriptions" });
  }
});

// Update prescription delivery status
app.put("/pharmacy/prescriptions/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this prescription" });
    }

    prescription.deliveryStatus = status;
    await prescription.save();

    res.json({ message: "Status updated successfully", prescription });
  } catch (error) {
    console.error("Error updating prescription status:", error);
    res.status(500).json({ message: "Error updating prescription status" });
  }
});

// Get prescription details
app.get("/pharmacy/prescriptions/:id", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id)
      .populate("appointmentId")
      .populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription details:", error);
    res.status(500).json({ message: "Error fetching prescription details" });
  }
});

// Get files for a specific prescription (for pharmacy)
app.get("/pharmacy/prescriptions/:id/files", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    const files = await File.find({
      _id: { $in: prescription.files },
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching prescription files:", error);
    res.status(500).json({ message: "Error fetching prescription files" });
  }
});

// Endpoint to end video call and reset callStatus
app.post("/video-call/end", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    appointment.callStatus = "none";
    await appointment.save();
    res.json({ message: "Video call ended", appointment });
  } catch (error) {
    console.error("Error ending video call:", error);
    res.status(500).json({ message: "Error ending video call" });
  }
});

// Basic route
app.get("/", (req, res) => {
  res.send("E-Health API is running");
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const jwt = require("jsonwebtoken");
const { OpenAI } = require("openai");
const auth = require("./auth");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();
const { RtcTokenBuilder, RtcRole } = require("agora-token");

const app = express();

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/jpg",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only PDF, DOC, DOCX, and image files are allowed."
        ),
        false
      );
    }
  },
});

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() =>
    console.log("MongoDB Connected Successfully to ehealth_data database")
  )
  .catch((err) => console.log("MongoDB Connection Error:", err));

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  doctorName: { type: String, required: true },
  doctorId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  specialty: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Doctor = mongoose.model("Doctor", doctorSchema);

// Patient Schema
const patientSchema = new mongoose.Schema({
  patientName: { type: String, required: true },
  patientId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  contact: { type: String },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Patient = mongoose.model("Patient", patientSchema);

// Pharmacy Schema
const pharmacySchema = new mongoose.Schema({
  pharmacyName: { type: String, required: true },
  pharmacyId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  address: { type: String, required: true },
  contact: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Pharmacy = mongoose.model("Pharmacy", pharmacySchema);

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  specialty: { type: String, required: true },
  doctor: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  reason: { type: String, required: true },
  phone: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "confirmed", "rescheduled", "cancelled"],
    default: "pending",
  },
  callStatus: {
    type: String,
    enum: ["none", "started"],
    default: "none",
  },
  createdAt: { type: Date, default: Date.now },
});

const Appointment = mongoose.model("Appointment", appointmentSchema);

// Prescription Schema
const prescriptionSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  doctorId: { type: String, required: true },
  patientId: { type: String, required: true },
  description: { type: String, required: true },
  files: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "File",
    },
  ],
  deliveryStatus: {
    type: String,
    enum: ["pending", "sent", "rejected", "delivered"],
    default: "pending",
  },
  deliveryDetails: {
    name: String,
    phone: String,
    address: String,
    city: String,
    pharmacy: String,
  },
  createdAt: { type: Date, default: Date.now },
});

const Prescription = mongoose.model("Prescription", prescriptionSchema);

// File Schema for prescription attachments
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  path: { type: String, required: true },
  url: { type: String, required: true },
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  uploadedBy: { type: String, required: true }, // doctorId
  createdAt: { type: Date, default: Date.now },
});

const File = mongoose.model("File", fileSchema);

// Sensor Data Schema
const sensorDataSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  ecg: { type: String },
  bloodPressure: {
    systolic: { type: Number },
    diastolic: { type: Number },
  },
  oxygenSaturation: { type: Number },
  respirationRate: { type: Number },
  temperature: { type: Number },
  timestamp: { type: Date, default: Date.now },
});

const SensorData = mongoose.model("SensorData", sensorDataSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  sender: {
    type: String,
    enum: ["doctor", "patient"],
    required: true,
  },
  text: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const Message = mongoose.model("Message", messageSchema);

// Doctor Registration Route
app.post("/doctors/register", async (req, res) => {
  try {
    const { doctorName, doctorId, email, password, specialty } = req.body;

    // Check if doctor already exists
    const existingDoctor = await Doctor.findOne({
      $or: [{ email }, { doctorId }],
    });

    if (existingDoctor) {
      return res.status(400).json({
        message: "Doctor with this email or ID already exists",
      });
    }

    // Create new doctor
    const doctor = new Doctor({
      doctorName,
      doctorId,
      email,
      password, // Note: In production, you should hash the password
      specialty,
    });

    await doctor.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Doctor registered successfully",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering doctor",
    });
  }
});

// Patient Registration Route
app.post("/patients/register", async (req, res) => {
  try {
    const { patientName, patientId, email, contact, password } = req.body;

    // Check if patient already exists
    const existingPatient = await Patient.findOne({
      $or: [{ email }, { patientId }],
    });

    if (existingPatient) {
      return res.status(400).json({
        message: "Patient with this email or ID already exists",
      });
    }

    // Create new patient
    const patient = new Patient({
      patientName,
      patientId,
      email,
      contact,
      password,
    });

    await patient.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Patient registered successfully",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering patient",
    });
  }
});

// Doctor Login Route
app.post("/doctors/login", async (req, res) => {
  try {
    const { doctorId, password } = req.body;

    // Find doctor by doctorId
    const doctor = await Doctor.findOne({ doctorId });

    if (!doctor) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Check password (Note: In production, use proper password comparison with hashed passwords)
    if (doctor.password !== password) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Doctor Profile Route
app.get("/doctors/profile", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    res.json({
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Patient Login Route
app.post("/patients/login", async (req, res) => {
  try {
    const { patientId, password } = req.body;

    // Find patient by patientId
    const patient = await Patient.findOne({ patientId });

    if (!patient) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Check password
    if (patient.password !== password) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Patient Profile Route
app.get("/patients/profile", auth, async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }
    res.json(patient);
  } catch (error) {
    console.error("Error fetching patient profile:", error);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// Update Patient Profile Route
app.put("/patients/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, contact, password } = req.body;

    // Find the patient by ID from the auth token
    const patient = await Patient.findById(req.user.id);

    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }

    // Check if email is being changed and if it's already taken
    if (email && email !== patient.email) {
      const existingPatient = await Patient.findOne({ email });
      if (existingPatient) {
        return res.status(400).json({ message: "Email already in use" });
      }
    }

    // Update patient information
    patient.patientName = name || patient.patientName;
    patient.email = email || patient.email;
    patient.contact = contact || patient.contact;

    // Only update password if a new one is provided
    if (password) {
      patient.password = password; // Note: In production, hash the password
    }

    await patient.save();

    res.json({
      message: "Profile updated successfully",
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

// Pharmacy Registration Route
app.post("/pharmacies/register", async (req, res) => {
  try {
    const { pharmacyName, pharmacyId, email, address, contact, password } =
      req.body;

    // Check if pharmacy already exists
    const existingPharmacy = await Pharmacy.findOne({
      $or: [{ email }, { pharmacyId }],
    });

    if (existingPharmacy) {
      return res.status(400).json({
        message: "Pharmacy with this email or ID already exists",
      });
    }

    // Create new pharmacy
    const pharmacy = new Pharmacy({
      pharmacyName,
      pharmacyId,
      email,
      address,
      contact,
      password,
    });

    await pharmacy.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Pharmacy registered successfully",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering pharmacy",
    });
  }
});

// Pharmacy Login Route
app.post("/pharmacies/login", async (req, res) => {
  try {
    const { pharmacyId, password } = req.body;

    // Find pharmacy by pharmacyId
    const pharmacy = await Pharmacy.findOne({ pharmacyId });

    if (!pharmacy) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Check password
    if (pharmacy.password !== password) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Protected Pharmacy Routes
app.get("/pharmacies/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({ message: "Pharmacy not found" });
    }
    res.json(pharmacy);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacy profile" });
  }
});

// ChatGPT Endpoint
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body;

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content:
            "You are a helpful medical assistant chatbot. Provide accurate and helpful information about health-related topics. Always remind users to consult healthcare professionals for medical advice.",
        },
        {
          role: "user",
          content: message,
        },
      ],
      max_tokens: 150,
    });

    res.json({
      reply: completion.choices[0].message.content,
    });
  } catch (error) {
    console.error("ChatGPT API Error:", error);
    res.status(500).json({
      message: "Error processing your request",
    });
  }
});

// Doctor Profile Update Route
app.put("/doctors/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const doctorId = req.user.id;

    // Find doctor by ID
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Update fields
    if (name) doctor.doctorName = name;
    if (email) doctor.email = email;
    if (password) doctor.password = password; // Note: In production, hash the password

    await doctor.save();

    res.json({
      message: "Profile updated successfully",
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Get Pharmacy Profile Route
app.get("/pharmacy/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    res.json({
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Update Pharmacy Profile Route
app.put("/pharmacy/profileupdate", auth, async (req, res) => {
  try {
    const { pharmacyName, email, address, contact, password } = req.body;
    const pharmacyId = req.user.id;

    // Find pharmacy by ID
    const pharmacy = await Pharmacy.findById(pharmacyId);
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    // Update fields
    if (pharmacyName) pharmacy.pharmacyName = pharmacyName;
    if (email) pharmacy.email = email;
    if (address) pharmacy.address = address;
    if (contact) pharmacy.contact = contact;
    if (password) pharmacy.password = password; // Note: In production, hash the password

    await pharmacy.save();

    res.json({
      message: "Profile updated successfully",
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Appointment Routes
// Get all appointments for a patient
app.get("/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({ date: -1, time: -1 });
    res.json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Create new appointment
app.post("/appointments", auth, async (req, res) => {
  try {
    const { patientId, specialty, doctor, date, time, reason, phone } =
      req.body;

    const appointment = new Appointment({
      patientId,
      specialty,
      doctor,
      date,
      time,
      reason,
      phone,
    });

    await appointment.save();
    res.status(201).json({
      message: "Appointment created successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error creating appointment:", error);
    res.status(500).json({ message: "Error creating appointment" });
  }
});

// Delete appointment
app.delete("/appointments/:id", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findByIdAndDelete(req.params.id);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({ message: "Appointment deleted successfully" });
  } catch (error) {
    console.error("Error deleting appointment:", error);
    res.status(500).json({ message: "Error deleting appointment" });
  }
});

// Update appointment status
app.patch("/appointments/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const appointment = await Appointment.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({
      message: "Appointment status updated successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error updating appointment status:", error);
    res.status(500).json({ message: "Error updating appointment status" });
  }
});

// Get all doctors grouped by specialty
app.get("/doctors", async (req, res) => {
  try {
    const doctors = await Doctor.find({}, "doctorName specialty");
    const doctorsBySpecialty = doctors.reduce((acc, doctor) => {
      if (!acc[doctor.specialty]) {
        acc[doctor.specialty] = [];
      }
      acc[doctor.specialty].push(doctor.doctorName);
      return acc;
    }, {});
    res.json(doctorsBySpecialty);
  } catch (error) {
    console.error("Error fetching doctors:", error);
    res.status(500).json({ message: "Error fetching doctors" });
  }
});

// Get Doctor's Appointments
app.get("/doctors/appointments", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const appointments = await Appointment.find({
      doctor: doctor.doctorName,
    }).sort({
      date: -1,
      time: -1,
    });

    res.status(200).json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Accept Appointment
app.put("/doctors/appointments/:id/accept", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "confirmed";
    await appointment.save();

    res.status(200).json({ message: "Appointment accepted", appointment });
  } catch (error) {
    console.error("Error accepting appointment:", error);
    res.status(500).json({ message: "Error accepting appointment" });
  }
});

// Reschedule Appointment
app.put("/doctors/appointments/:id/reschedule", auth, async (req, res) => {
  try {
    const { date, time, note } = req.body;
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }
    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.date = date;
    appointment.time = time;
    appointment.note = note;
    appointment.status = "rescheduled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rescheduled", appointment });
  } catch (error) {
    console.error("Error rescheduling appointment:", error);
    res.status(500).json({ message: "Error rescheduling appointment" });
  }
});

// Reject Appointment
app.put("/doctors/appointments/:id/reject", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "cancelled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rejected", appointment });
  } catch (error) {
    console.error("Error rejecting appointment:", error);
    res.status(500).json({ message: "Error rejecting appointment" });
  }
});

// Upload Prescription
app.post("/prescriptions", auth, async (req, res) => {
  try {
    const { appointmentId, description, files } = req.body;

    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const prescription = new Prescription({
      appointmentId,
      doctorId: doctor.doctorId,
      patientId: appointment.patientId,
      description,
      files: files || [],
    });

    await prescription.save();
    res.status(201).json(prescription);
  } catch (error) {
    console.error("Error uploading prescription:", error);
    res.status(500).json({ message: "Error uploading prescription" });
  }
});

// Upload file for prescription
app.post(
  "/prescriptions/upload-file",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { appointmentId } = req.body;

      // Verify appointment exists
      const appointment = await Appointment.findById(appointmentId);
      if (!appointment) {
        return res.status(404).json({ message: "Appointment not found" });
      }

      const doctor = await Doctor.findById(req.user.id).select("-password");
      if (!doctor) {
        return res.status(404).json({
          message: "Doctor not found",
        });
      }

      // Create file record
      const file = new File({
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path,
        url: `${req.protocol}://${req.get("host")}/uploads/${
          req.file.filename
        }`,
        appointmentId: appointmentId,
        uploadedBy: doctor.doctorId,
      });

      await file.save();
      res.status(201).json(file);
    } catch (error) {
      console.error("Error uploading file:", error);
      res.status(500).json({ message: "Error uploading file" });
    }
  }
);

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res
        .status(400)
        .json({ message: "File too large. Maximum size is 10MB." });
    }
    return res.status(400).json({ message: error.message });
  }

  if (error.message.includes("Invalid file type")) {
    return res.status(400).json({ message: error.message });
  }

  next(error);
});

// Get files for an appointment
app.get("/prescriptions/:appointmentId/files", auth, async (req, res) => {
  try {
    const files = await File.find({
      appointmentId: req.params.appointmentId,
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching files:", error);
    res.status(500).json({ message: "Error fetching files" });
  }
});

// Delete file
app.delete("/prescriptions/file/:fileId", auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Check if doctor owns the file
    if (file.uploadedBy !== doctor.doctorId) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this file" });
    }

    // Delete physical file
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    // Delete file record
    await File.findByIdAndDelete(req.params.fileId);

    // Remove file reference from prescription
    await Prescription.updateMany(
      { files: req.params.fileId },
      { $pull: { files: req.params.fileId } }
    );

    res.json({ message: "File deleted successfully" });
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).json({ message: "Error deleting file" });
  }
});

// Get Patient's Sensor Data
app.get("/sensor-data/:patientId", auth, async (req, res) => {
  try {
    const sensorData = await SensorData.find({
      patientId: req.params.patientId,
    })
      .sort({ timestamp: -1 })
      .limit(1);

    if (!sensorData.length) {
      return res.status(404).json({ message: "No sensor data found" });
    }

    res.json(sensorData[0]);
  } catch (error) {
    console.error("Error fetching sensor data:", error);
    res.status(500).json({ message: "Error fetching sensor data" });
  }
});

// Update Sensor Data
app.post("/sensor-data", auth, async (req, res) => {
  try {
    const {
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    } = req.body;

    const sensorData = new SensorData({
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    });

    await sensorData.save();
    res.status(201).json(sensorData);
  } catch (error) {
    console.error("Error updating sensor data:", error);
    res.status(500).json({ message: "Error updating sensor data" });
  }
});

// Get Prescription for Appointment
app.get("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    }).populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "No prescription found" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription:", error);
    res.status(500).json({ message: "Error fetching prescription" });
  }
});

// Get Patient Appointments
app.get("/patient/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({
      date: -1,
      time: -1,
    });
    const appointmentsWithPrescriptions = await Promise.all(
      appointments.map(async (appointment) => {
        const prescription = await Prescription.findOne({
          appointmentId: appointment._id,
        });
        return {
          ...appointment.toObject(),
          prescription: prescription ? prescription.description : null,
          deliveryStatus: prescription ? prescription.deliveryStatus : null,
          prescriptionId: prescription ? prescription._id : null,
        };
      })
    );
    res.json(appointmentsWithPrescriptions);
  } catch (error) {
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Update Prescription Delivery Status
app.post("/prescription/delivery/:prescriptionId", auth, async (req, res) => {
  try {
    const { name, phone, address, city, pharmacy } = req.body;
    const prescription = await Prescription.findById(req.params.prescriptionId);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    prescription.deliveryStatus = "sent";
    prescription.deliveryDetails = {
      name,
      phone,
      address,
      city,
      pharmacy,
    };

    await prescription.save();
    res.json({ message: "Delivery status updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating delivery status" });
  }
});

// Get Video Call Token
app.post("/video-call/token", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    // Set callStatus to 'started' when doctor or patient initiates the call
    if (req.user.role === "doctor" || req.user.role === "patient") {
      appointment.callStatus = "started";
      await appointment.save();
    }

    // Generate a unique channel name for the video call
    const channelName = `appointment-${appointmentId}`;

    // Generate Agora token
    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERTIFICATE;
    const uid = 0; // Set to 0 to let Agora assign a uid
    const role = RtcRole.PUBLISHER; // Use RtcRole enum
    const privilegeExpiredTs = 3600; // Token valid for 1 hour

    const token = RtcTokenBuilder.buildTokenWithUid(
      appID,
      appCertificate,
      channelName,
      uid,
      role,
      privilegeExpiredTs
    );

    // Generate a JWT token for authentication
    const jwtToken = jwt.sign(
      {
        appointmentId,
        patientId: appointment.patientId,
        doctorId: appointment.doctorId,
        role: req.user.role,
        channelName,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token: jwtToken,
      agoraToken: token,
      channelName,
      appID: process.env.AGORA_APP_ID,
    });
  } catch (error) {
    console.error("Error generating video call token:", error);
    res.status(500).json({ message: "Error generating video call token" });
  }
});

// Get Pharmacies by City
app.get("/pharmacies/:address", async (req, res) => {
  try {
    const { address } = req.params;
    const pharmacies = await Pharmacy.find({ address: address });
    res.json(pharmacies);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacies" });
  }
});

// Get All Cities with Pharmacies
app.get("/pharmacy-address", async (req, res) => {
  try {
    const address = await Pharmacy.distinct("address");

    res.json(address);
  } catch (error) {
    res.status(500).json({ message: "Error fetching cities" });
  }
});

// Update Prescription
app.put("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const { description, files } = req.body;
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    });

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (prescription.doctorId !== doctor.doctorId) {
      return res.status(403).json({
        message: "Not authorized to modify this prescription",
      });
    }

    prescription.description = description;
    if (files) {
      prescription.files = files;
    }
    await prescription.save();
    res.json(prescription);
  } catch (error) {
    console.error("Error updating prescription:", error);
    res.status(500).json({ message: "Error updating prescription" });
  }
});

// Get chat messages for an appointment
app.get("/messages/:appointmentId", auth, async (req, res) => {
  try {
    const { appointmentId } = req.params;
    const messages = await Message.find({ appointmentId })
      .sort({ timestamp: 1 })
      .limit(50);
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Error fetching messages" });
  }
});

// Send a new message
app.post("/messages", auth, async (req, res) => {
  try {
    const { appointmentId, text } = req.body;
    const sender = req.user.role === "doctor" ? "doctor" : "patient";

    const message = new Message({
      appointmentId,
      sender,
      text,
    });

    await message.save();
    res.status(201).json(message);
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Error sending message" });
  }
});

// Get all prescriptions for a pharmacy
app.get("/pharmacy/prescriptions", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    const prescriptions = await Prescription.find({
      "deliveryDetails.pharmacy": pharmacy.pharmacyId,
    })
      .populate("appointmentId")
      .populate("files")
      .sort({ createdAt: -1 });

    res.json(prescriptions);
  } catch (error) {
    console.error("Error fetching prescriptions:", error);
    res.status(500).json({ message: "Error fetching prescriptions" });
  }
});

// Update prescription delivery status
app.put("/pharmacy/prescriptions/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this prescription" });
    }

    prescription.deliveryStatus = status;
    await prescription.save();

    res.json({ message: "Status updated successfully", prescription });
  } catch (error) {
    console.error("Error updating prescription status:", error);
    res.status(500).json({ message: "Error updating prescription status" });
  }
});

// Get prescription details
app.get("/pharmacy/prescriptions/:id", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id)
      .populate("appointmentId")
      .populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription details:", error);
    res.status(500).json({ message: "Error fetching prescription details" });
  }
});

// Get files for a specific prescription (for pharmacy)
app.get("/pharmacy/prescriptions/:id/files", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    const files = await File.find({
      _id: { $in: prescription.files },
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching prescription files:", error);
    res.status(500).json({ message: "Error fetching prescription files" });
  }
});

// Endpoint to end video call and reset callStatus
app.post("/video-call/end", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    appointment.callStatus = "none";
    await appointment.save();
    res.json({ message: "Video call ended", appointment });
  } catch (error) {
    console.error("Error ending video call:", error);
    res.status(500).json({ message: "Error ending video call" });
  }
});

// Basic route
app.get("/", (req, res) => {
  res.send("E-Health API is running");
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const fs = require("fs");
require("dotenv").config();
const { RtcTokenBuilder, RtcRole } = require("agora-token");

// Google Cloud Storage
const { Storage } = require("@google-cloud/storage");
const storage = new Storage();
const bucketName =
  process.env.GOOGLE_CLOUD_STORAGE_BUCKET || "e-health-uploads";

const app = express();

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Create uploads directory if it doesn't exist (for local development)
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads (memory storage for Cloud Storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/jpg",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only PDF, DOC, DOCX, and image files are allowed."
        ),
        false
      );
    }
  },
});

// Function to upload file to Google Cloud Storage
async function uploadToCloudStorage(file, filename) {
  try {
    const bucket = storage.bucket(bucketName);
    const blob = bucket.file(filename);

    await blob.save(file.buffer, {
      metadata: {
        contentType: file.mimetype,
      },
    });

    // Make the file publicly accessible
    await blob.makePublic();

    return `https://storage.googleapis.com/${bucketName}/${filename}`;
  } catch (error) {
    console.error("Error uploading to Cloud Storage:", error);
    throw error;
  }
}

// Function to delete file from Google Cloud Storage
async function deleteFromCloudStorage(filename) {
  try {
    const bucket = storage.bucket(bucketName);
    const file = bucket.file(filename);
    await file.delete();
  } catch (error) {
    console.error("Error deleting from Cloud Storage:", error);
    throw error;
  }
}

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from uploads directory (for local development)
if (process.env.NODE_ENV !== "production") {
  app.use("/uploads", express.static(path.join(__dirname, "uploads")));
}

// Serve uploaded files with proper error handling
app.get("/uploads/:filename", (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, "uploads", filename);

  // Check if file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      message: "File not found",
      error: "The requested file does not exist on the server",
    });
  }

  // Serve the file
  res.sendFile(filePath);
});

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() =>
    console.log("MongoDB Connected Successfully to ehealth_data database")
  )
  .catch((err) => console.log("MongoDB Connection Error:", err));

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  doctorName: { type: String, required: true },
  doctorId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  specialty: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Doctor = mongoose.model("Doctor", doctorSchema);

// Patient Schema
const patientSchema = new mongoose.Schema({
  patientName: { type: String, required: true },
  patientId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  contact: { type: String },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Patient = mongoose.model("Patient", patientSchema);

// Pharmacy Schema
const pharmacySchema = new mongoose.Schema({
  pharmacyName: { type: String, required: true },
  pharmacyId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  address: { type: String, required: true },
  contact: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Pharmacy = mongoose.model("Pharmacy", pharmacySchema);

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  specialty: { type: String, required: true },
  doctor: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  reason: { type: String, required: true },
  phone: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "confirmed", "rescheduled", "cancelled"],
    default: "pending",
  },
  callStatus: {
    type: String,
    enum: ["none", "started"],
    default: "none",
  },
  createdAt: { type: Date, default: Date.now },
});

const Appointment = mongoose.model("Appointment", appointmentSchema);

// Prescription Schema
const prescriptionSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  doctorId: { type: String, required: true },
  patientId: { type: String, required: true },
  description: { type: String, required: true },
  files: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "File",
    },
  ],
  deliveryStatus: {
    type: String,
    enum: ["pending", "sent", "rejected", "delivered"],
    default: "pending",
  },
  deliveryDetails: {
    name: String,
    phone: String,
    address: String,
    city: String,
    pharmacy: String,
  },
  createdAt: { type: Date, default: Date.now },
});

const Prescription = mongoose.model("Prescription", prescriptionSchema);

// File Schema for prescription attachments
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  path: { type: String, required: true },
  url: { type: String, required: true },
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  uploadedBy: { type: String, required: true }, // doctorId
  createdAt: { type: Date, default: Date.now },
});

const File = mongoose.model("File", fileSchema);

// Sensor Data Schema
const sensorDataSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  ecg: { type: String },
  bloodPressure: {
    systolic: { type: Number },
    diastolic: { type: Number },
  },
  oxygenSaturation: { type: Number },
  respirationRate: { type: Number },
  temperature: { type: Number },
  timestamp: { type: Date, default: Date.now },
});

const SensorData = mongoose.model("SensorData", sensorDataSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Appointment",
    required: true,
  },
  sender: {
    type: String,
    enum: ["doctor", "patient"],
    required: true,
  },
  text: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const Message = mongoose.model("Message", messageSchema);

// Doctor Registration Route
app.post("/doctors/register", async (req, res) => {
  try {
    const { doctorName, doctorId, email, password, specialty } = req.body;

    // Check if doctor already exists
    const existingDoctor = await Doctor.findOne({
      $or: [{ email }, { doctorId }],
    });

    if (existingDoctor) {
      return res.status(400).json({
        message: "Doctor with this email or ID already exists",
      });
    }

    // Create new doctor
    const doctor = new Doctor({
      doctorName,
      doctorId,
      email,
      password, // Note: In production, you should hash the password
      specialty,
    });

    await doctor.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Doctor registered successfully",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering doctor",
    });
  }
});

// Patient Registration Route
app.post("/patients/register", async (req, res) => {
  try {
    const { patientName, patientId, email, contact, password } = req.body;

    // Check if patient already exists
    const existingPatient = await Patient.findOne({
      $or: [{ email }, { patientId }],
    });

    if (existingPatient) {
      return res.status(400).json({
        message: "Patient with this email or ID already exists",
      });
    }

    // Create new patient
    const patient = new Patient({
      patientName,
      patientId,
      email,
      contact,
      password,
    });

    await patient.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Patient registered successfully",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering patient",
    });
  }
});

// Doctor Login Route
app.post("/doctors/login", async (req, res) => {
  try {
    const { doctorId, password } = req.body;

    // Find doctor by doctorId
    const doctor = await Doctor.findOne({ doctorId });

    if (!doctor) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Check password (Note: In production, use proper password comparison with hashed passwords)
    if (doctor.password !== password) {
      return res.status(401).json({
        message: "Invalid Doctor ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: doctor._id, role: "doctor" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
        role: "doctor",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Doctor Profile Route
app.get("/doctors/profile", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    res.json({
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Patient Login Route
app.post("/patients/login", async (req, res) => {
  try {
    const { patientId, password } = req.body;

    // Find patient by patientId
    const patient = await Patient.findOne({ patientId });

    if (!patient) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Check password
    if (patient.password !== password) {
      return res.status(401).json({
        message: "Invalid Patient ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: patient._id, role: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
        role: "patient",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Get Patient Profile Route
app.get("/patients/profile", auth, async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }
    res.json(patient);
  } catch (error) {
    console.error("Error fetching patient profile:", error);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// Update Patient Profile Route
app.put("/patients/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, contact, password } = req.body;

    // Find the patient by ID from the auth token
    const patient = await Patient.findById(req.user.id);

    if (!patient) {
      return res.status(404).json({ message: "Patient not found" });
    }

    // Check if email is being changed and if it's already taken
    if (email && email !== patient.email) {
      const existingPatient = await Patient.findOne({ email });
      if (existingPatient) {
        return res.status(400).json({ message: "Email already in use" });
      }
    }

    // Update patient information
    patient.patientName = name || patient.patientName;
    patient.email = email || patient.email;
    patient.contact = contact || patient.contact;

    // Only update password if a new one is provided
    if (password) {
      patient.password = password; // Note: In production, hash the password
    }

    await patient.save();

    res.json({
      message: "Profile updated successfully",
      patient: {
        patientName: patient.patientName,
        patientId: patient.patientId,
        email: patient.email,
        contact: patient.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

// Pharmacy Registration Route
app.post("/pharmacies/register", async (req, res) => {
  try {
    const { pharmacyName, pharmacyId, email, address, contact, password } =
      req.body;

    // Check if pharmacy already exists
    const existingPharmacy = await Pharmacy.findOne({
      $or: [{ email }, { pharmacyId }],
    });

    if (existingPharmacy) {
      return res.status(400).json({
        message: "Pharmacy with this email or ID already exists",
      });
    }

    // Create new pharmacy
    const pharmacy = new Pharmacy({
      pharmacyName,
      pharmacyId,
      email,
      address,
      contact,
      password,
    });

    await pharmacy.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "Pharmacy registered successfully",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering pharmacy",
    });
  }
});

// Pharmacy Login Route
app.post("/pharmacies/login", async (req, res) => {
  try {
    const { pharmacyId, password } = req.body;

    // Find pharmacy by pharmacyId
    const pharmacy = await Pharmacy.findOne({ pharmacyId });

    if (!pharmacy) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Check password
    if (pharmacy.password !== password) {
      return res.status(401).json({
        message: "Invalid Pharmacy ID or password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: pharmacy._id, role: "pharmacy" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
        role: "pharmacy",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error during login",
    });
  }
});

// Protected Pharmacy Routes
app.get("/pharmacies/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({ message: "Pharmacy not found" });
    }
    res.json(pharmacy);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacy profile" });
  }
});

// ChatGPT Endpoint
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body;

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content:
            "You are a helpful medical assistant chatbot. Provide accurate and helpful information about health-related topics. Always remind users to consult healthcare professionals for medical advice.",
        },
        {
          role: "user",
          content: message,
        },
      ],
      max_tokens: 150,
    });

    res.json({
      reply: completion.choices[0].message.content,
    });
  } catch (error) {
    console.error("ChatGPT API Error:", error);
    res.status(500).json({
      message: "Error processing your request",
    });
  }
});

// Doctor Profile Update Route
app.put("/doctors/profileupdate", auth, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const doctorId = req.user.id;

    // Find doctor by ID
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Update fields
    if (name) doctor.doctorName = name;
    if (email) doctor.email = email;
    if (password) doctor.password = password; // Note: In production, hash the password

    await doctor.save();

    res.json({
      message: "Profile updated successfully",
      doctor: {
        doctorName: doctor.doctorName,
        doctorId: doctor.doctorId,
        email: doctor.email,
        specialty: doctor.specialty,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Get Pharmacy Profile Route
app.get("/pharmacy/profile", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    res.json({
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({
      message: "Error fetching profile",
    });
  }
});

// Update Pharmacy Profile Route
app.put("/pharmacy/profileupdate", auth, async (req, res) => {
  try {
    const { pharmacyName, email, address, contact, password } = req.body;
    const pharmacyId = req.user.id;

    // Find pharmacy by ID
    const pharmacy = await Pharmacy.findById(pharmacyId);
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    // Update fields
    if (pharmacyName) pharmacy.pharmacyName = pharmacyName;
    if (email) pharmacy.email = email;
    if (address) pharmacy.address = address;
    if (contact) pharmacy.contact = contact;
    if (password) pharmacy.password = password; // Note: In production, hash the password

    await pharmacy.save();

    res.json({
      message: "Profile updated successfully",
      pharmacy: {
        pharmacyName: pharmacy.pharmacyName,
        pharmacyId: pharmacy.pharmacyId,
        email: pharmacy.email,
        address: pharmacy.address,
        contact: pharmacy.contact,
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      message: "Error updating profile",
    });
  }
});

// Appointment Routes
// Get all appointments for a patient
app.get("/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({ date: -1, time: -1 });
    res.json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Create new appointment
app.post("/appointments", auth, async (req, res) => {
  try {
    const { patientId, specialty, doctor, date, time, reason, phone } =
      req.body;

    const appointment = new Appointment({
      patientId,
      specialty,
      doctor,
      date,
      time,
      reason,
      phone,
    });

    await appointment.save();
    res.status(201).json({
      message: "Appointment created successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error creating appointment:", error);
    res.status(500).json({ message: "Error creating appointment" });
  }
});

// Delete appointment
app.delete("/appointments/:id", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findByIdAndDelete(req.params.id);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({ message: "Appointment deleted successfully" });
  } catch (error) {
    console.error("Error deleting appointment:", error);
    res.status(500).json({ message: "Error deleting appointment" });
  }
});

// Update appointment status
app.patch("/appointments/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const appointment = await Appointment.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    res.json({
      message: "Appointment status updated successfully",
      appointment,
    });
  } catch (error) {
    console.error("Error updating appointment status:", error);
    res.status(500).json({ message: "Error updating appointment status" });
  }
});

// Get all doctors grouped by specialty
app.get("/doctors", async (req, res) => {
  try {
    const doctors = await Doctor.find({}, "doctorName specialty");
    const doctorsBySpecialty = doctors.reduce((acc, doctor) => {
      if (!acc[doctor.specialty]) {
        acc[doctor.specialty] = [];
      }
      acc[doctor.specialty].push(doctor.doctorName);
      return acc;
    }, {});
    res.json(doctorsBySpecialty);
  } catch (error) {
    console.error("Error fetching doctors:", error);
    res.status(500).json({ message: "Error fetching doctors" });
  }
});

// Get Doctor's Appointments
app.get("/doctors/appointments", auth, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const appointments = await Appointment.find({
      doctor: doctor.doctorName,
    }).sort({
      date: -1,
      time: -1,
    });

    res.status(200).json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Accept Appointment
app.put("/doctors/appointments/:id/accept", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "confirmed";
    await appointment.save();

    res.status(200).json({ message: "Appointment accepted", appointment });
  } catch (error) {
    console.error("Error accepting appointment:", error);
    res.status(500).json({ message: "Error accepting appointment" });
  }
});

// Reschedule Appointment
app.put("/doctors/appointments/:id/reschedule", auth, async (req, res) => {
  try {
    const { date, time, note } = req.body;
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }
    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.date = date;
    appointment.time = time;
    appointment.note = note;
    appointment.status = "rescheduled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rescheduled", appointment });
  } catch (error) {
    console.error("Error rescheduling appointment:", error);
    res.status(500).json({ message: "Error rescheduling appointment" });
  }
});

// Reject Appointment
app.put("/doctors/appointments/:id/reject", auth, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (appointment.doctor !== doctor.doctorName) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this appointment" });
    }

    appointment.status = "cancelled";
    await appointment.save();

    res.status(200).json({ message: "Appointment rejected", appointment });
  } catch (error) {
    console.error("Error rejecting appointment:", error);
    res.status(500).json({ message: "Error rejecting appointment" });
  }
});

// Upload Prescription
app.post("/prescriptions", auth, async (req, res) => {
  try {
    const { appointmentId, description, files } = req.body;

    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    const prescription = new Prescription({
      appointmentId,
      doctorId: doctor.doctorId,
      patientId: appointment.patientId,
      description,
      files: files || [],
    });

    await prescription.save();
    res.status(201).json(prescription);
  } catch (error) {
    console.error("Error uploading prescription:", error);
    res.status(500).json({ message: "Error uploading prescription" });
  }
});

// Upload file for prescription
app.post(
  "/prescriptions/upload-file",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { appointmentId } = req.body;

      // Verify appointment exists
      const appointment = await Appointment.findById(appointmentId);
      if (!appointment) {
        return res.status(404).json({ message: "Appointment not found" });
      }

      const doctor = await Doctor.findById(req.user.id).select("-password");
      if (!doctor) {
        return res.status(404).json({
          message: "Doctor not found",
        });
      }

      // Generate unique filename
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      const filename = `file-${uniqueSuffix}${path.extname(
        req.file.originalname
      )}`;

      // Upload file to Cloud Storage
      const fileUrl = await uploadToCloudStorage(req.file, filename);

      // Create file record
      const file = new File({
        filename: filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: fileUrl, // Store the URL
        url: fileUrl,
        appointmentId: appointmentId,
        uploadedBy: doctor.doctorId,
      });

      await file.save();
      res.status(201).json(file);
    } catch (error) {
      console.error("Error uploading file:", error);
      res.status(500).json({ message: "Error uploading file" });
    }
  }
);

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res
        .status(400)
        .json({ message: "File too large. Maximum size is 10MB." });
    }
    return res.status(400).json({ message: error.message });
  }

  if (error.message.includes("Invalid file type")) {
    return res.status(400).json({ message: error.message });
  }

  next(error);
});

// Get files for an appointment
app.get("/prescriptions/:appointmentId/files", auth, async (req, res) => {
  try {
    const files = await File.find({
      appointmentId: req.params.appointmentId,
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching files:", error);
    res.status(500).json({ message: "Error fetching files" });
  }
});

// Delete file
app.delete("/prescriptions/file/:fileId", auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    // Check if doctor owns the file
    if (file.uploadedBy !== doctor.doctorId) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this file" });
    }

    // Delete from Cloud Storage if it's a Cloud Storage URL
    if (file.path && file.path.startsWith("https://storage.googleapis.com/")) {
      try {
        await deleteFromCloudStorage(file.filename);
      } catch (error) {
        console.error("Error deleting from Cloud Storage:", error);
        // Continue with deletion even if Cloud Storage deletion fails
      }
    } else if (file.path && fs.existsSync(file.path)) {
      // Delete local file (for development)
      fs.unlinkSync(file.path);
    }

    // Delete file record
    await File.findByIdAndDelete(req.params.fileId);

    // Remove file reference from prescription
    await Prescription.updateMany(
      { files: req.params.fileId },
      { $pull: { files: req.params.fileId } }
    );

    res.json({ message: "File deleted successfully" });
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).json({ message: "Error deleting file" });
  }
});

// Get Patient's Sensor Data
app.get("/sensor-data/:patientId", auth, async (req, res) => {
  try {
    const sensorData = await SensorData.find({
      patientId: req.params.patientId,
    })
      .sort({ timestamp: -1 })
      .limit(1);

    if (!sensorData.length) {
      return res.status(404).json({ message: "No sensor data found" });
    }

    res.json(sensorData[0]);
  } catch (error) {
    console.error("Error fetching sensor data:", error);
    res.status(500).json({ message: "Error fetching sensor data" });
  }
});

// Update Sensor Data
app.post("/sensor-data", auth, async (req, res) => {
  try {
    const {
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    } = req.body;

    const sensorData = new SensorData({
      patientId,
      ecg,
      bloodPressure,
      oxygenSaturation,
      respirationRate,
      temperature,
    });

    await sensorData.save();
    res.status(201).json(sensorData);
  } catch (error) {
    console.error("Error updating sensor data:", error);
    res.status(500).json({ message: "Error updating sensor data" });
  }
});

// Get Prescription for Appointment
app.get("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    }).populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "No prescription found" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription:", error);
    res.status(500).json({ message: "Error fetching prescription" });
  }
});

// Get Patient Appointments
app.get("/patient/appointments/:patientId", auth, async (req, res) => {
  try {
    const appointments = await Appointment.find({
      patientId: req.params.patientId,
    }).sort({
      date: -1,
      time: -1,
    });
    const appointmentsWithPrescriptions = await Promise.all(
      appointments.map(async (appointment) => {
        const prescription = await Prescription.findOne({
          appointmentId: appointment._id,
        });
        return {
          ...appointment.toObject(),
          prescription: prescription ? prescription.description : null,
          deliveryStatus: prescription ? prescription.deliveryStatus : null,
          prescriptionId: prescription ? prescription._id : null,
        };
      })
    );
    res.json(appointmentsWithPrescriptions);
  } catch (error) {
    res.status(500).json({ message: "Error fetching appointments" });
  }
});

// Update Prescription Delivery Status
app.post("/prescription/delivery/:prescriptionId", auth, async (req, res) => {
  try {
    const { name, phone, address, city, pharmacy } = req.body;
    const prescription = await Prescription.findById(req.params.prescriptionId);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    prescription.deliveryStatus = "sent";
    prescription.deliveryDetails = {
      name,
      phone,
      address,
      city,
      pharmacy,
    };

    await prescription.save();
    res.json({ message: "Delivery status updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating delivery status" });
  }
});

// Get Video Call Token
app.post("/video-call/token", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    // Set callStatus to 'started' when doctor or patient initiates the call
    if (req.user.role === "doctor" || req.user.role === "patient") {
      appointment.callStatus = "started";
      await appointment.save();
    }

    // Generate a unique channel name for the video call
    const channelName = `appointment-${appointmentId}`;

    // Generate Agora token
    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERTIFICATE;
    const uid = 0; // Set to 0 to let Agora assign a uid
    const role = RtcRole.PUBLISHER; // Use RtcRole enum
    const privilegeExpiredTs = 3600; // Token valid for 1 hour

    const token = RtcTokenBuilder.buildTokenWithUid(
      appID,
      appCertificate,
      channelName,
      uid,
      role,
      privilegeExpiredTs
    );

    // Generate a JWT token for authentication
    const jwtToken = jwt.sign(
      {
        appointmentId,
        patientId: appointment.patientId,
        doctorId: appointment.doctorId,
        role: req.user.role,
        channelName,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token: jwtToken,
      agoraToken: token,
      channelName,
      appID: process.env.AGORA_APP_ID,
    });
  } catch (error) {
    console.error("Error generating video call token:", error);
    res.status(500).json({ message: "Error generating video call token" });
  }
});

// Get Pharmacies by City
app.get("/pharmacies/:address", async (req, res) => {
  try {
    const { address } = req.params;
    const pharmacies = await Pharmacy.find({ address: address });
    res.json(pharmacies);
  } catch (error) {
    res.status(500).json({ message: "Error fetching pharmacies" });
  }
});

// Get All Cities with Pharmacies
app.get("/pharmacy-address", async (req, res) => {
  try {
    const address = await Pharmacy.distinct("address");

    res.json(address);
  } catch (error) {
    res.status(500).json({ message: "Error fetching cities" });
  }
});

// Update Prescription
app.put("/prescriptions/:appointmentId", auth, async (req, res) => {
  try {
    const { description, files } = req.body;
    const prescription = await Prescription.findOne({
      appointmentId: req.params.appointmentId,
    });

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const doctor = await Doctor.findById(req.user.id).select("-password");
    if (!doctor) {
      return res.status(404).json({
        message: "Doctor not found",
      });
    }

    if (prescription.doctorId !== doctor.doctorId) {
      return res.status(403).json({
        message: "Not authorized to modify this prescription",
      });
    }

    prescription.description = description;
    if (files) {
      prescription.files = files;
    }
    await prescription.save();
    res.json(prescription);
  } catch (error) {
    console.error("Error updating prescription:", error);
    res.status(500).json({ message: "Error updating prescription" });
  }
});

// Get chat messages for an appointment
app.get("/messages/:appointmentId", auth, async (req, res) => {
  try {
    const { appointmentId } = req.params;
    const messages = await Message.find({ appointmentId })
      .sort({ timestamp: 1 })
      .limit(50);
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Error fetching messages" });
  }
});

// Send a new message
app.post("/messages", auth, async (req, res) => {
  try {
    const { appointmentId, text } = req.body;
    const sender = req.user.role === "doctor" ? "doctor" : "patient";

    const message = new Message({
      appointmentId,
      sender,
      text,
    });

    await message.save();
    res.status(201).json(message);
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Error sending message" });
  }
});

// Get all prescriptions for a pharmacy
app.get("/pharmacy/prescriptions", auth, async (req, res) => {
  try {
    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    const prescriptions = await Prescription.find({
      "deliveryDetails.pharmacy": pharmacy.pharmacyId,
    })
      .populate("appointmentId")
      .populate("files")
      .sort({ createdAt: -1 });

    res.json(prescriptions);
  } catch (error) {
    console.error("Error fetching prescriptions:", error);
    res.status(500).json({ message: "Error fetching prescriptions" });
  }
});

// Update prescription delivery status
app.put("/pharmacy/prescriptions/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this prescription" });
    }

    prescription.deliveryStatus = status;
    await prescription.save();

    res.json({ message: "Status updated successfully", prescription });
  } catch (error) {
    console.error("Error updating prescription status:", error);
    res.status(500).json({ message: "Error updating prescription status" });
  }
});

// Get prescription details
app.get("/pharmacy/prescriptions/:id", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id)
      .populate("appointmentId")
      .populate("files");

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    res.json(prescription);
  } catch (error) {
    console.error("Error fetching prescription details:", error);
    res.status(500).json({ message: "Error fetching prescription details" });
  }
});

// Get files for a specific prescription (for pharmacy)
app.get("/pharmacy/prescriptions/:id/files", auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id);

    if (!prescription) {
      return res.status(404).json({ message: "Prescription not found" });
    }

    const pharmacy = await Pharmacy.findById(req.user.id).select("-password");
    if (!pharmacy) {
      return res.status(404).json({
        message: "Pharmacy not found",
      });
    }

    if (prescription.deliveryDetails.pharmacy !== pharmacy.pharmacyId) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this prescription" });
    }

    const files = await File.find({
      _id: { $in: prescription.files },
    }).sort({ createdAt: -1 });

    res.json(files);
  } catch (error) {
    console.error("Error fetching prescription files:", error);
    res.status(500).json({ message: "Error fetching prescription files" });
  }
});

// Endpoint to end video call and reset callStatus
app.post("/video-call/end", auth, async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }
    appointment.callStatus = "none";
    await appointment.save();
    res.json({ message: "Video call ended", appointment });
  } catch (error) {
    console.error("Error ending video call:", error);
    res.status(500).json({ message: "Error ending video call" });
  }
});

// Basic route
app.get("/", (req, res) => {
  res.send("E-Health API is running");
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
