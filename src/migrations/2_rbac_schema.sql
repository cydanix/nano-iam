-- RBAC schema: roles and permissions

CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    PRIMARY KEY (role_id, permission)
);

-- Seed default roles
INSERT INTO roles (id, name, description) VALUES
  ('a0000000-0000-0000-0000-000000000001', 'admin', 'Full access to org resources and member management'),
  ('a0000000-0000-0000-0000-000000000002', 'member', 'Standard access to org resources'),
  ('a0000000-0000-0000-0000-000000000003', 'viewer', 'Read-only access to org resources');

-- Default permissions per role
INSERT INTO role_permissions (role_id, permission) VALUES
  -- admin
  ('a0000000-0000-0000-0000-000000000001', 'org:manage'),
  ('a0000000-0000-0000-0000-000000000001', 'members:invite'),
  ('a0000000-0000-0000-0000-000000000001', 'members:remove'),
  ('a0000000-0000-0000-0000-000000000001', 'members:read'),
  ('a0000000-0000-0000-0000-000000000001', 'settings:read'),
  ('a0000000-0000-0000-0000-000000000001', 'settings:write'),
  ('a0000000-0000-0000-0000-000000000001', 'notifications:read'),
  ('a0000000-0000-0000-0000-000000000001', 'notifications:write'),
  ('a0000000-0000-0000-0000-000000000001', 'audit_log:read'),
  -- member
  ('a0000000-0000-0000-0000-000000000002', 'members:read'),
  ('a0000000-0000-0000-0000-000000000002', 'settings:read'),
  ('a0000000-0000-0000-0000-000000000002', 'notifications:read'),
  ('a0000000-0000-0000-0000-000000000002', 'notifications:write'),
  ('a0000000-0000-0000-0000-000000000002', 'audit_log:read'),
  -- viewer
  ('a0000000-0000-0000-0000-000000000003', 'members:read'),
  ('a0000000-0000-0000-0000-000000000003', 'settings:read'),
  ('a0000000-0000-0000-0000-000000000003', 'notifications:read'),
  ('a0000000-0000-0000-0000-000000000003', 'audit_log:read');
