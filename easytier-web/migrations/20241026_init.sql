-- # Entity schema.

-- Create `users` table.
create table if not exists users (
    id integer primary key autoincrement,
    username text not null unique,
    password text not null
);

-- Create `groups` table.
create table if not exists groups (
    id integer primary key autoincrement,
    name text not null unique
);

-- Create `permissions` table.
create table if not exists permissions (
    id integer primary key autoincrement,
    name text not null unique
);

-- # Join tables.

-- Create `users_groups` table for many-to-many relationships between users and groups.
create table if not exists users_groups (
    user_id integer references users(id),
    group_id integer references groups(id),
    primary key (user_id, group_id)
);

-- Create `groups_permissions` table for many-to-many relationships between groups and permissions.
create table if not exists groups_permissions (
    group_id integer references groups(id),
    permission_id integer references permissions(id),
    primary key (group_id, permission_id)
);

-- # Fixture hydration.
-- 不再插入任何默认用户、组或权限。
-- 由管理员在部署后手动添加需要的用户和组。
