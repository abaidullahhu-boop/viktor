import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UserRole } from '../common/enums';
import { JwtPayload } from '../common/interfaces';
import { AppConfig } from '../config/configuration';
import { User, Workspace } from '../database/entities';
import { SlackService } from '../slack/slack.service';
import { UsersService } from '../users/users.service';
import { WorkspacesService } from '../workspaces/workspaces.service';

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResult extends AuthTokens {
  user: User;
  workspace: Workspace;
}

/** A workspace the user belongs to, as exposed by `GET /auth/workspaces`. */
export interface WorkspaceMembership {
  workspaceId: string;
  name: string;
  slackTeamId: string;
  role: UserRole;
  isCurrent: boolean;
}

const REFRESH_TOKEN_SALT_ROUNDS = 10;

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly usersService: UsersService,
    private readonly workspacesService: WorkspacesService,
    private readonly slackService: SlackService,
  ) {}

  /** Returns the Slack "Add to Slack" install URL. */
  getSlackInstallUrl(state: string): string {
    return this.slackService.buildInstallUrl(state);
  }

  /**
   * Completes the Slack OAuth flow: resolves the Slack identity, provisions the
   * workspace + user, and issues a fresh access/refresh token pair.
   */
  async handleSlackCallback(code: string): Promise<AuthResult> {
    const identity = await this.slackService.exchangeCodeForIdentity(code);

    const workspace = await this.workspacesService.upsertFromSlack({
      slackTeamId: identity.slackTeamId,
      name: identity.teamName,
      slackBotToken: identity.botToken,
    });

    const user = await this.usersService.upsertFromSlack({
      workspaceId: workspace.id,
      slackUserId: identity.slackUserId,
      name: identity.name,
      email: identity.email,
      avatarUrl: identity.avatarUrl,
    });

    const tokens = await this.issueTokens(user);

    return { ...tokens, user, workspace };
  }

  /** Validates a refresh token, rotates it, and returns a new token pair. */
  async refresh(refreshToken: string): Promise<AuthTokens> {
    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(refreshToken, {
        secret: this.configService.get('jwt.refreshSecret', { infer: true }),
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user || !user.refreshTokenHash || !user.isActive) {
      throw new UnauthorizedException('Refresh token is no longer valid');
    }

    const matches = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!matches) {
      throw new UnauthorizedException('Refresh token mismatch');
    }

    return this.issueTokens(user);
  }

  /** Invalidates the stored refresh token for a user (logout). */
  async logout(userId: string): Promise<void> {
    await this.usersService.setRefreshTokenHash(userId, null);
  }

  /** Returns the current user's profile. */
  async getCurrentUser(userId: string): Promise<User> {
    return this.usersService.findByIdOrFail(userId);
  }

  /** Lists every workspace the user is a member of, flagging the current one. */
  async listWorkspaces(userId: string): Promise<WorkspaceMembership[]> {
    const user = await this.usersService.findByIdOrFail(userId);
    const memberships = await this.usersService.findMembershipsOf(user);

    return memberships.map((membership) => ({
      workspaceId: membership.workspaceId,
      name: membership.workspace.name,
      slackTeamId: membership.workspace.slackTeamId,
      role: membership.role,
      isCurrent: membership.workspaceId === user.workspaceId,
    }));
  }

  /**
   * Issues a token pair scoped to another workspace the user belongs to.
   * The caller is expected to refetch `/auth/me` with the new access token.
   */
  async switchWorkspace(userId: string, workspaceId: string): Promise<AuthTokens> {
    const user = await this.usersService.findByIdOrFail(userId);
    const memberships = await this.usersService.findMembershipsOf(user);

    const target = memberships.find((membership) => membership.workspaceId === workspaceId);
    if (!target) {
      throw new ForbiddenException('You are not a member of that workspace');
    }

    return this.issueTokens(target);
  }

  private async issueTokens(user: User): Promise<AuthTokens> {
    if (!user.workspaceId) {
      throw new BadRequestException('User is not linked to a workspace');
    }

    const payload: JwtPayload = {
      sub: user.id,
      workspaceId: user.workspaceId,
      slackUserId: user.slackUserId,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('jwt.secret', { infer: true }),
      expiresIn: this.configService.get('jwt.expiresIn', { infer: true }),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('jwt.refreshSecret', { infer: true }),
      expiresIn: this.configService.get('jwt.refreshExpiresIn', { infer: true }),
    });

    const refreshTokenHash = await bcrypt.hash(refreshToken, REFRESH_TOKEN_SALT_ROUNDS);
    await this.usersService.setRefreshTokenHash(user.id, refreshTokenHash);

    return { accessToken, refreshToken };
  }
}
