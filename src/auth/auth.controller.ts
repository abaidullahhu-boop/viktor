import { randomUUID } from 'crypto';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import { CurrentUser, Public } from '../common/decorators';
import { AppConfig } from '../config/configuration';
import { User } from '../database/entities';
import { AuthService, AuthTokens, WorkspaceMembership } from './auth.service';
import { RefreshTokenDto, SlackCallbackDto, SwitchWorkspaceDto } from './dto';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /** Step 1 — redirect the browser to Slack's OAuth consent screen. */
  @Public()
  @Get('slack/install')
  install(@Res() res: Response): void {
    const state = randomUUID();
    const url = this.authService.getSlackInstallUrl(state);
    res.redirect(url);
  }

  /**
   * Step 2 — Slack redirects here with a `code`. We provision the workspace/user
   * and bounce the browser back to the frontend with the issued tokens.
   */
  @Public()
  @Get('slack/callback')
  async slackCallback(@Query() query: SlackCallbackDto, @Res() res: Response): Promise<void> {
    if (query.error) {
      throw new BadRequestException(`Slack authorization failed: ${query.error}`);
    }
    if (!query.code) {
      throw new BadRequestException('Missing OAuth code from Slack');
    }

    const result = await this.authService.handleSlackCallback(query.code);

    const frontendUrl = this.configService.get('app.frontendUrl', { infer: true });
    const redirectUrl = new URL('/auth/callback', frontendUrl);
    redirectUrl.searchParams.set('accessToken', result.accessToken);
    redirectUrl.searchParams.set('refreshToken', result.refreshToken);

    res.redirect(redirectUrl.toString());
  }

  /** Exchange a valid refresh token for a new access/refresh pair. */
  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshTokenDto): Promise<{ accessToken: string; refreshToken: string }> {
    return this.authService.refresh(dto.refreshToken);
  }

  /** Invalidate the current user's refresh token. */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser('userId') userId: string): Promise<{ success: boolean }> {
    if (!userId) {
      throw new UnauthorizedException();
    }
    await this.authService.logout(userId);
    return { success: true };
  }

  /** Return the currently authenticated user. */
  @Get('me')
  me(@CurrentUser('userId') userId: string): Promise<User> {
    return this.authService.getCurrentUser(userId);
  }

  /** List every workspace the current user is a member of. */
  @Get('workspaces')
  listWorkspaces(@CurrentUser('userId') userId: string): Promise<WorkspaceMembership[]> {
    return this.authService.listWorkspaces(userId);
  }

  /** Issue a token pair scoped to another workspace the user belongs to. */
  @Post('switch-workspace')
  @HttpCode(HttpStatus.OK)
  switchWorkspace(
    @CurrentUser('userId') userId: string,
    @Body() dto: SwitchWorkspaceDto,
  ): Promise<AuthTokens> {
    return this.authService.switchWorkspace(userId, dto.workspaceId);
  }
}
