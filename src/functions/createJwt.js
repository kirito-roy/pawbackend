import { jwtVerify } from 'jose';

export class JWTClass {
  // Verify JWT Token
  async verifyToken(token, secret) {
    try {
      const { payload } = await jwtVerify(
        token,
        new TextEncoder().encode(secret)
      );
      return payload;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }
}