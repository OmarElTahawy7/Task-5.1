import dotenv from 'dotenv';
dotenv.config();
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { connectDB } from '../config/db.js';
import { Instructor } from '../models/Instructor.js';

// Upgrade legacy plaintext passwords without deleting or replacing accounts.
const bcryptHash = /^\$2[aby]\$\d{2}\$/;

async function migrate() {
  await connectDB();
  try {
    const instructors = await Instructor.find({}).select('+password');
    let migrated = 0;

    for (const instructor of instructors) {
      const legacyPassword = instructor.password;
      if (typeof legacyPassword !== 'string' || bcryptHash.test(legacyPassword)) continue;

      const passwordHash = await bcrypt.hash(legacyPassword, 10);
      const result = await Instructor.updateOne(
        { _id: instructor._id, password: legacyPassword },
        { $set: { password: passwordHash } }
      );
      migrated += result.modifiedCount;
    }

    console.log(`Hashed ${migrated} legacy instructor password(s).`);
  } finally {
    await mongoose.disconnect();
  }
}

migrate().catch(async (err) => {
  console.error('Instructor password migration failed:', err.message);
  await mongoose.disconnect();
  process.exitCode = 1;
});
