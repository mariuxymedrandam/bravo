import { createHash, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { asyncHandler } from '../../core/async-handler.js';
import { AppError, ConflictError, NotFoundError, UnauthorizedError } from '../../core/errors.js';
import { created } from '../../core/http.js';
import { transaction } from '../../database/transaction.js';

const passwordSchema = z.string()
  .min(8)
  .max(72)
  .regex(/[A-Za-z]/, 'La contraseña debe contener una letra.')
  .regex(/[0-9]/, 'La contraseña debe contener un número.');

const bootstrapAdminSchema = z.object({
  nombres: z.string().trim().min(2).max(80),
  apellidos: z.string().trim().min(2).max(80),
  correo: z.string().trim().email().max(150),
  password: passwordSchema,
  telefono: z.string().trim().max(25).nullable().optional(),
  fecha_nacimiento: z.string().date().nullable().optional(),
});

function secureEquals(received: string, expected: string) {
  const receivedHash = createHash('sha256').update(received).digest();
  const expectedHash = createHash('sha256').update(expected).digest();
  return timingSafeEqual(receivedHash, expectedHash);
}

export const bootstrapRouter = Router();

bootstrapRouter.use(rateLimit({
  windowMs: 60 * 60_000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
}));

bootstrapRouter.post('/admin', asyncHandler(async (req, res) => {
  // Si no hay clave configurada, la ruta queda efectivamente deshabilitada.
  if (!env.BOOTSTRAP_ADMIN_KEY) {
    throw new NotFoundError('La inicialización del administrador no está habilitada.');
  }

  const suppliedKey = req.get('x-bootstrap-key') ?? '';
  if (!suppliedKey || !secureEquals(suppliedKey, env.BOOTSTRAP_ADMIN_KEY)) {
    throw new UnauthorizedError('Clave de inicialización inválida.');
  }

  const input = bootstrapAdminSchema.parse(req.body);
  const email = input.correo.toLowerCase();

  const admin = await transaction(async (client) => {
    // Bloquear la fila del rol serializa intentos simultáneos de bootstrap.
    const role = (await client.query(
      `SELECT id_rol
       FROM rol
       WHERE codigo='ADMINISTRADOR' AND activo=TRUE AND deleted_at IS NULL
       FOR UPDATE`,
    )).rows[0] as { id_rol: string } | undefined;

    if (!role) {
      throw new AppError(
        503,
        'No existe el rol ADMINISTRADOR activo. Restaura primero la estructura y los catálogos de la base de datos.',
        'BOOTSTRAP_ROLE_MISSING',
      );
    }

    const currentAdmin = await client.query(
      `SELECT 1
       FROM usuario_rol ur
       JOIN usuario u ON u.id_usuario=ur.id_usuario AND u.deleted_at IS NULL
       WHERE ur.id_rol=$1 AND ur.deleted_at IS NULL
       LIMIT 1`,
      [role.id_rol],
    );
    if (currentAdmin.rowCount) {
      throw new ConflictError('El administrador inicial ya fue creado. Esta ruta ya no puede utilizarse.');
    }

    const duplicate = await client.query(
      'SELECT 1 FROM usuario WHERE LOWER(correo)=$1 AND deleted_at IS NULL',
      [email],
    );
    if (duplicate.rowCount) {
      throw new ConflictError('Ya existe una cuenta con ese correo. Utiliza otro correo para el administrador inicial.');
    }

    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = (await client.query(
      `INSERT INTO usuario(
         nombres,apellidos,correo,password_hash,telefono,fecha_nacimiento,
         activo,correo_verificado
       )
       VALUES($1,$2,$3,$4,$5,$6,TRUE,TRUE)
       RETURNING id_usuario,nombres,apellidos,correo,telefono,fecha_nacimiento,activo,correo_verificado`,
      [
        input.nombres,
        input.apellidos,
        email,
        passwordHash,
        input.telefono ?? null,
        input.fecha_nacimiento ?? null,
      ],
    )).rows[0] as {
      id_usuario: string;
      nombres: string;
      apellidos: string;
      correo: string;
      telefono: string | null;
      fecha_nacimiento: string | null;
      activo: boolean;
      correo_verificado: boolean;
    };

    await client.query(
      'INSERT INTO usuario_rol(id_usuario,id_rol,asignado_por) VALUES($1,$2,$1)',
      [user.id_usuario, role.id_rol],
    );

    return { ...user, rol: 'ADMINISTRADOR' };
  });

  return created(res, {
    ...admin,
    message: 'Administrador inicial creado correctamente. Retira BOOTSTRAP_ADMIN_KEY del servidor y vuelve a desplegar.',
  });
}));
