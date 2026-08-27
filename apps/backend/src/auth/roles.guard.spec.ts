import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from '../roles.guard';
import { ROLES_KEY } from '../roles.decorator';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should allow access if no roles are required', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({ user: { role: 'student' } }) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(null);

    expect(guard.canActivate(mockContext)).toBe(true);
  });

  it('should allow access if user has required role', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({ user: { role: 'admin' } }) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin', 'instructor']);

    expect(guard.canActivate(mockContext)).toBe(true);
  });

  it('should throw ForbiddenException if user role not in required roles', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({ user: { role: 'student' } }) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin', 'instructor']);

    expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
  });

  it('should throw ForbiddenException if user has no role', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({ user: {} }) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);

    expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
  });

  it('should throw ForbiddenException if no user', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({}) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);

    expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
  });

  it('should return 403 with descriptive message', () => {
    const mockContext = {
      getHandler: () => ({}),
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => ({ user: { role: 'student' } }) }),
    } as unknown as ExecutionContext;

    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin', 'instructor']);

    try {
      guard.canActivate(mockContext);
    } catch (error) {
      if (error instanceof ForbiddenException) {
        expect(error.getStatus()).toBe(403);
        expect(error.getResponse()).toContain('admin');
      }
    }
  });
});
