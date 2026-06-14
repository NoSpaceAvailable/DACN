-- HTTP Core (parsers, cookie handling, etc.)

DELIMITER $$

DROP PROCEDURE IF EXISTS `sign_cookie`$$
CREATE PROCEDURE `sign_cookie` (IN `cookie_value` TEXT, OUT `signed` TEXT)
BEGIN
    DECLARE secret, signature TEXT;
    SET secret = (SELECT `value` FROM `config` WHERE `name` = 'signing_key');
    SET signature = SHA2(CONCAT(cookie_value, secret), 256);
    SET signed = CONCAT(signature, LOWER(HEX(cookie_value)));
END$$


DROP PROCEDURE IF EXISTS `verify_cookie`$$
CREATE PROCEDURE `verify_cookie` (IN `signed_value` TEXT, OUT `cookie_value` BLOB, OUT `valid` BOOLEAN)
BEGIN
    DECLARE secret, signature TEXT;
    SET secret = (SELECT `value` FROM `config` WHERE `name` = 'signing_key');
    SET signature = SUBSTR(signed_value FROM 1 FOR 64);
    SET cookie_value = UNHEX(SUBSTR(signed_value FROM 65));
    SET valid = (SELECT SHA2(CONCAT(cookie_value, secret), 256) = signature);
END$$


DROP PROCEDURE IF EXISTS `handle_request`$$
CREATE PROCEDURE `handle_request` (IN `method` TEXT, IN `path` TEXT, IN `body` TEXT, OUT `resp` TEXT)
BEGIN
    -- Reject POST bodies that contain 'signing_key' substring
    IF method = 'POST' AND INSTR(body, 'signing_key') > 0 THEN
        SET resp = 'Forbidden';
    ELSE
        CALL dispatch(method, path, body, resp);
    END IF;
END$$

DELIMITER ;
