# Operations: Adopting an Existing Database

For deployments whose database was created with `drizzle-kit push` and therefore has no migrations journal. Fresh installs never need this, `npm run db:migrate` builds them from migration zero.

## Why the guard exists

`db:migrate` replays every migration the journal has not recorded. Against a push managed database that means recreating tables that already exist, which fails at best and mangles the schema at worst. So the migrator refuses to touch a populated database that has no journal and points here instead. The refusal is the safety net, baselining is the fix.

## The procedure

1. **Back up.** A journal baseline only inserts bookkeeping rows, but you are about to change how this database is managed forever, so snapshot it first
2. **Dry run.** The tool probes the live schema for each migration's marker object and reports the contiguous prefix it finds:

   ```bash
   export DATABASE_URL=postgresql://...
   npm run db:baseline
   ```

   Expect output like `Schema reflects 9 migration(s)` with the list. If it reports fewer than the newest migration, that is correct, the remainder will be applied as real migrations afterwards
3. **Apply.** Writes `drizzle.__drizzle_migrations` with one row per detected migration, using the real file hashes and the journal timestamps:

   ```bash
   npm run db:baseline -- --apply
   ```

4. **Migrate.** From here on this is the standard deploy step:

   ```bash
   npm run db:migrate
   ```

   It applies only migrations newer than the baseline and is a no-op when the schema was already current

## Rollback

The baseline itself is trivially reversible, it created bookkeeping and nothing else:

```sql
DROP SCHEMA drizzle CASCADE;
```

That returns the database to push managed state. If `db:migrate` afterwards applied real migrations and those need undoing, restore the backup from step 1, the platform ships no down migrations by design.

## When detection refuses

The tool aborts when the schema matches a later migration but not an earlier one. No push or migrate history produces that shape, it means the schema was hand edited. Reconcile manually: compare `\d` output against the migration files, fix the drift, rerun the dry run.

## Recovering from an interrupted baseline

The baseline writes the journal table and all its rows in one transaction, so an interruption commits everything or nothing, you cannot be left with a half written journal. Two things enforce this:

- `db:baseline --apply` validates an existing journal against the schema's expected migration prefix. A complete journal is a safe no-op while an incomplete or inconsistent journal is rejected
- `db:migrate` performs the same prefix validation before applying anything. It compares row counts, migration timestamps and migration file hashes, then points here when recovery is required

If you hit that refusal, the journal is untrustworthy. Drop it and baseline again from a known good schema:

```sql
DROP SCHEMA drizzle CASCADE;
```

```bash
npm run db:baseline -- --apply
npm run db:migrate
```
