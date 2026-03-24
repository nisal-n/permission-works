-- Supabase audit enhancements for permission-set logs
alter table if exists public.ifs_permission_sets
    add column if not exists created_env text;

alter table if exists public.ifs_permission_sets
    add column if not exists action_type text default 'New';

update public.ifs_permission_sets
set action_type = coalesce(nullif(action_type, ''), 'New')
where action_type is null or action_type = '';

alter table if exists public.ifs_permission_set_grants
    add column if not exists created_env text;

alter table if exists public.ifs_permission_set_grants
    add column if not exists action_type text default 'New';

update public.ifs_permission_set_grants
set action_type = coalesce(nullif(action_type, ''), 'New')
where action_type is null or action_type = '';

create index if not exists idx_ifs_permission_sets_name_created_at
    on public.ifs_permission_sets(permission_set_name, created_at desc);

create index if not exists idx_ifs_permission_set_grants_parent_created_at
    on public.ifs_permission_set_grants(permission_set_id, granted_at asc);
