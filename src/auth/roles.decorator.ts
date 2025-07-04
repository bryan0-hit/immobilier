import { SetMetadata } from '@nestjs/common';
import { UserRole } from '.././enums/enums';

export const Roles = (...roles: UserRole[]) => SetMetadata('roles', roles);