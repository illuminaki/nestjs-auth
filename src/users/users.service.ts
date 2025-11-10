import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  // Simulamos una base de datos en memoria
  private users: User[] = [];
  private currentId = 1;

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Verificar si el email ya existe
    const existingUser = this.users.find(u => u.email === createUserDto.email);
    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Crear el nuevo usuario
    const newUser: User = {
      id: this.currentId++,
      email: createUserDto.email,
      password: hashedPassword,
      name: createUserDto.name,
      createdAt: new Date(),
    };

    this.users.push(newUser);
    return newUser;
  }

  findAll(): User[] {
    // Retornar usuarios sin la contraseña
    return this.users.map(({ password, ...user }) => user as User);
  }

  findOne(id: number): User {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    
    // Retornar sin la contraseña
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword as User;
  }

  findByEmail(email: string): User | undefined {
    return this.users.find(u => u.email === email);
  }

  update(id: number, updateUserDto: UpdateUserDto): User {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    this.users[userIndex] = { ...this.users[userIndex], ...updateUserDto };
    const { password, ...userWithoutPassword } = this.users[userIndex];
    return userWithoutPassword as User;
  }

  remove(id: number): void {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    this.users.splice(userIndex, 1);
  }
}
