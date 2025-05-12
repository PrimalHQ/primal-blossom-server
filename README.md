<br />
<div align="center">
    <img src="https://primal.net/assets/logo_fire-409917ad.svg" alt="Logo" width="80" height="80">
</div>

### Usage

Create Postgres database, edit `primal-blossom-server-config.json` to match your database settings, and run the following command:

    nix develop -c sh -c 'DATABASE_URL="postgresql://..." RUST_BACKTRACE=1 $cargo +nightly run --quiet -- --config-file primal-blossom-server-config.json'

