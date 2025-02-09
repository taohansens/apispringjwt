create table tb_user
(
    id       bigserial primary key,
    email    varchar(255),
    password varchar(255),
    username varchar(255),
    role     varchar(255)
);