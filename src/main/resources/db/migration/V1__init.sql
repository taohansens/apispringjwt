create table tb_user
(
    id       bigserial primary key,
    email    varchar(255),
    password varchar(255),
    username varchar(255)
);


create table tb_roles
(
    id       bigserial primary key,
    name     varchar(255) not null
);

create table user_roles
(
    user_id  bigint not null,
    role_id  bigint not null,
    primary key (user_id, role_id),
    foreign key (user_id) references tb_user(id),
    foreign key (role_id) references tb_roles(id)
);

insert into tb_roles (name) values ('USER'), ('ADMIN'), ('SUPERADMIN');