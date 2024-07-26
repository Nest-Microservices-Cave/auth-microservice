import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { envs } from 'src/config';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected!!');
  }

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });
      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({ status: 401, message: 'Invalid Token' });
    }
  }

  async register(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });
      if (user)
        throw new RpcException({
          status: 400,
          message: 'User already exists.',
        });
      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10),
          name: name,
        },
      });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...rest } = newUser;
      return { user: rest, token: await this.signJWT(rest) };
    } catch (err) {
      throw new RpcException({ status: 400, message: err.message });
    }
  }

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });
      if (!user)
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials.',
        });
      const isPasswordValid = bcrypt.compareSync(password, user.password);
      if (!isPasswordValid)
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials.',
        });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...rest } = user;
      return { user: rest, token: await this.signJWT(rest) };
    } catch (err) {
      throw new RpcException({ status: 400, message: err.message });
    }
  }
}
