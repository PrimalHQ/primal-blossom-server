create table if not exists media_uploads
(
    pubkey              bytea        not null,
    type                varchar(50)  not null,
    key                 jsonb        not null,
    created_at          bigint       not null,
    path                text         not null,
    size                bigint       not null,
    mimetype            varchar(200) not null,
    category            varchar(100) not null,
    category_confidence real         not null,
    width               bigint       not null,
    height              bigint       not null,
    duration            real         not null,
    sha256              bytea,
    moderation_category varchar,
    media_block_id      uuid
);
create index if not exists media_uploads_created_at on media_uploads (created_at desc);
create index if not exists media_uploads_pubkey on media_uploads (pubkey);
create index if not exists media_uploads_path on media_uploads (path);
create index if not exists media_uploads_sha256 on media_uploads (sha256);
create index if not exists media_uploads_pubkey_idx on media_uploads (pubkey);
create index if not exists media_uploads_created_at_idx on media_uploads (created_at desc);
create index if not exists media_uploads_sha256_idx on media_uploads (sha256);
create index if not exists media_uploads_path_idx on media_uploads (path);
create index if not exists media_uploads_media_block_id_idx on media_uploads (media_block_id);

create table if not exists media_storage
(
    media_url        varchar not null,
    storage_provider varchar not null,
    added_at         bigint  not null,
    key              varchar not null,
    h                varchar not null,
    ext              varchar not null,
    content_type     varchar not null,
    size             bigint  not null,
    sha256           bytea,
    media_block_id   uuid,
    primary key (h, storage_provider)
);
create index if not exists media_storage_added_at_idx on media_storage (added_at);
create index if not exists media_storage_h_idx on media_storage (h);
create index if not exists media_storage_key_sha256_idx on media_storage ((key::jsonb ->> 'sha256'::text));
create index if not exists media_storage_sha256_idx on media_storage (sha256);
create index if not exists media_storage_media_url_idx on media_storage (media_url);
create index if not exists media_storage_media_block_id_idx on media_storage (media_block_id);

create table if not exists media_metadata_stripping
(
    sha256_before bytea     not null,
    sha256_after  bytea     not null,
    t             timestamp not null,
    extra         jsonb
);
create index if not exists media_metadata_stripping_sha256_before_idx on media_metadata_stripping (sha256_before);
create index if not exists media_metadata_stripping_sha256_after_idx on media_metadata_stripping (sha256_after);

