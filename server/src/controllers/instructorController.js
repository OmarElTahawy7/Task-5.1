import { Instructor } from '../models/Instructor.js';
import bcrypt from 'bcryptjs';
import Joi from 'joi';

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(80).required(),
  password: Joi.string().min(1).max(200).required()
}).unknown(false);

const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100)
}).unknown(false);

function rejectSanitizedInput(req, res) {
  if (!req.mongoSanitized) return false;
  res.status(400).json({ message: 'Invalid request input' });
  return true;
}

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    if (rejectSanitizedInput(req, res)) return;
    const { value, error } = loginSchema.validate(req.body, { convert: false });
    if (error) return res.status(400).json({ message: 'username and password must be strings' });

    const instructor = await Instructor.findOne({ username: value.username }).select('+password');

    if (!instructor || !(await bcrypt.compare(value.password, instructor.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    if (req.mongoSanitized) return res.json({ count: 0, instructors: [] });
    const { value, error } = searchSchema.validate(req.query, { convert: false });
    if (error) return res.status(400).json({ message: 'Only a plain name search is supported' });

    const filter = value.name
      ? { name: { $regex: escapeRegex(value.name), $options: 'i' } }
      : {};
    const instructors = await Instructor.find(filter)
      .select('name username department role')
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
