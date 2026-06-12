import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
import { UserRole } from '../common/enums';
import { User } from '../database/entities';

export interface UpsertUserFromSlackInput {
  workspaceId: string;
  slackUserId: string;
  name: string;
  email?: string | null;
  avatarUrl?: string | null;
  /** First user of a workspace becomes the admin. */
  role?: UserRole;
}

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async findByIdOrFail(id: string): Promise<User> {
    const user = await this.findById(id);
    if (!user) {
      throw new NotFoundException(`User ${id} not found`);
    }
    return user;
  }

  findBySlackIdentity(workspaceId: string, slackUserId: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { workspaceId, slackUserId } });
  }

  countByWorkspace(workspaceId: string): Promise<number> {
    return this.userRepository.count({ where: { workspaceId } });
  }

  /**
   * All active user records belonging to the same person across workspaces.
   * Slack user ids are team-scoped, so the email is the cross-workspace link
   * (with the slackUserId as a fallback for Enterprise Grid shared ids).
   */
  findMembershipsOf(user: User): Promise<User[]> {
    const where: FindOptionsWhere<User>[] = [{ slackUserId: user.slackUserId, isActive: true }];
    if (user.email) {
      where.push({ email: user.email, isActive: true });
    }
    return this.userRepository.find({
      where,
      relations: { workspace: true },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Creates or updates a user from their Slack identity. If the workspace has no
   * users yet, the new user is promoted to ADMIN.
   */
  async upsertFromSlack(input: UpsertUserFromSlackInput): Promise<User> {
    const existing = await this.findBySlackIdentity(input.workspaceId, input.slackUserId);

    if (existing) {
      existing.name = input.name;
      existing.email = input.email ?? existing.email;
      existing.avatarUrl = input.avatarUrl ?? existing.avatarUrl;
      existing.isActive = true;
      existing.lastActiveAt = new Date();
      return this.userRepository.save(existing);
    }

    const isFirstUser = (await this.countByWorkspace(input.workspaceId)) === 0;

    const user = this.userRepository.create({
      workspaceId: input.workspaceId,
      slackUserId: input.slackUserId,
      name: input.name,
      email: input.email ?? null,
      avatarUrl: input.avatarUrl ?? null,
      role: input.role ?? (isFirstUser ? UserRole.ADMIN : UserRole.MEMBER),
      isActive: true,
      lastActiveAt: new Date(),
    });

    return this.userRepository.save(user);
  }

  async setRefreshTokenHash(userId: string, refreshTokenHash: string | null): Promise<void> {
    await this.userRepository.update({ id: userId }, { refreshTokenHash });
  }

  async updateLastActive(userId: string): Promise<void> {
    await this.userRepository.update({ id: userId }, { lastActiveAt: new Date() });
  }
}
