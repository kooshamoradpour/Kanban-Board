import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const SECRET_KEY = process.env.JWT_SECRET || 'your_secret_key';

export const login = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Compare password with hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: '1h',
    });

    return res.json({ token }); 

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Internal server error' }); 
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
