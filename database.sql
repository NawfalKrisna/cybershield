-- CyberShield - Skema Database MySQL
-- Import: mysql -u root -p < database.sql

CREATE DATABASE IF NOT EXISTS cybershield
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cybershield;

-- 1. Aturan firewall
CREATE TABLE IF NOT EXISTS firewall_rules (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL,
  action      ENUM('allow','block') NOT NULL,
  ip_address  VARCHAR(18)  NOT NULL DEFAULT '*',   -- '*', IP tunggal, atau CIDR
  port        VARCHAR(11)  NOT NULL DEFAULT '*',   -- '*', angka, atau rentang a-b
  protocol    ENUM('TCP','UDP','ANY') NOT NULL DEFAULT 'TCP',
  is_active   TINYINT(1)   NOT NULL DEFAULT 1,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Log keamanan
CREATE TABLE IF NOT EXISTS security_logs (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip     VARCHAR(15)  NOT NULL,
  target_port   SMALLINT UNSIGNED NOT NULL,
  activity_type VARCHAR(150) NOT NULL,
  action_taken  ENUM('ALLOWED','BLOCKED') NOT NULL,
  INDEX idx_time (event_time),
  INDEX idx_ip (source_ip)
) ENGINE=InnoDB;

-- 3. Blacklist IP
CREATE TABLE IF NOT EXISTS blacklist_ips (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(18)  NOT NULL UNIQUE,
  reason     VARCHAR(200) NOT NULL DEFAULT '',
  added_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Data awal
INSERT INTO firewall_rules (name, action, ip_address, port, protocol, is_active) VALUES
  ('Izinkan HTTP',           'allow', '*',            '80',  'TCP', 1),
  ('Izinkan HTTPS',          'allow', '*',            '443', 'TCP', 1),
  ('Izinkan DNS',            'allow', '*',            '53',  'UDP', 1),
  ('Blokir Telnet',          'block', '*',            '23',  'TCP', 1),
  ('Izinkan SSH Admin (LAN)','allow', '192.168.1.0/24','22', 'TCP', 0);

INSERT INTO blacklist_ips (ip_address, reason) VALUES
  ('185.220.101.45', 'Node TOR exit - aktivitas scanning'),
  ('45.155.205.233', 'Sumber brute force SSH'),
  ('91.240.118.172', 'Server C2 malware');

INSERT INTO security_logs (event_time, source_ip, target_port, activity_type, action_taken) VALUES
  (NOW(), '203.0.113.25',   443,  'Lalu lintas normal (HTTPS)',   'ALLOWED'),
  (NOW(), '185.220.101.45', 22,   'IP Blacklist - koneksi ditolak','BLOCKED'),
  (NOW(), '198.51.100.77',  3389, 'Percobaan akses RDP',          'BLOCKED');
