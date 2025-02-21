import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}


declare module 'express-serve-static-core' {
  interface Request {
    user?: JwtPayload;
  }
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

export default authenticateToken;
