import { IsNotEmpty, IsUUID } from 'class-validator';

export class SwitchWorkspaceDto {
  @IsUUID()
  @IsNotEmpty()
  workspaceId!: string;
}
