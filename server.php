<?php
/*
If you put the whole webauthn directory in the www document root and put an index.php in there 
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/
// ASCII TEXT
// http://patorjk.com/software/taag/#p=display&h=0&c=c&f=ANSI%20Shadow&t=SomeThing

define('SYS_DEBUG', false);

include_once('webauthn.php');
include_once('CI/User_agent.php');

/* from https://github.com/2tvenom/CBOREncode :  */
include_once('CBOREncode/src/CBOR/CBOREncoder.php');
include_once('CBOREncode/src/CBOR/Types/CBORByteString.php');
include_once('CBOREncode/src/CBOR/CBORExceptions.php');

function EstablishDBCon() {

    $pdo = false;
    try{ 
		$pdo = new PDO('sqlite:database/users.sqlite3');
		$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$pdo->exec('CREATE TABLE IF NOT EXISTS "users" (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE ,
			"username" TEXT UNIQUE,
			"password" TEXT,
			"displayname" TEXT,
			"webauthnkeys" TEXT,
			"failed_login_attempts" INTEGER DEFAULT 0,
			"failed_login_ts" INTEGER,
			"lastlogin_on" TEXT,
			"created_on" TEXT
		)');

		$pdo->exec('CREATE TABLE IF NOT EXISTS "auth_tokens" (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE ,
			"selector" TEXT,
			"hashedvalidator" TEXT,
			"userid" INTEGER,
			"expires" INTEGER,
			"created_on" TEXT
		)');

		$pdo->exec('CREATE TABLE IF NOT EXISTS "login_attempts" (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE ,
			"username" TEXT,
			"reason" TEXT,
			"agent" TEXT,
			"ip" TEXT,
			"ts" INTEGER,
			"created_on" TEXT
		)');
		
		$pdo->exec('CREATE INDEX IF NOT EXISTS `username` ON `users` (`username` ASC)');
		$pdo->exec('CREATE INDEX IF NOT EXISTS `selector` ON `auth_tokens` ( `selector` ASC)');
    } catch (Exception $e) {
       logger('db connect', json_encode($e));
    }

    return $pdo;
}



function getUserById(PDO $pdo, $id = false) {

	if ($id) {
		$stmt = $pdo->prepare("SELECT * FROM users WHERE id=:id LIMIT 1");
		$stmt->bindValue(":id", $id, PDO::PARAM_INT);
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($row) {
			return (object) $row;
		} else {
			return false;
		}
	}

	return false;
}

function getUserByName(PDO $pdo, $username = false) {

	if ($username) {
		$stmt = $pdo->prepare("SELECT * FROM users WHERE username=:username LIMIT 1");
		$stmt->bindValue(":username", $username, PDO::PARAM_STR);
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($row) {
			return (object) $row;
		} else {
			return false;
		}
	}

	return false;
}

function addUser(PDO $pdo, $username = false, $password = false) {

	if ($username && $password) {
		$displayname = strtoupper('Mr. ' . $username);
		$pdo->beginTransaction();
		$stmt = $pdo->prepare("INSERT INTO users (username, password, displayname, webauthnkeys, lastlogin_on, created_on) VALUES (:username, :password, :displayname, :webauthnkeys, :lastlogin_on, :created_on)");
		$stmt->bindValue(":username", $username, PDO::PARAM_STR);
		$stmt->bindValue(":password", $password, PDO::PARAM_STR);
		$stmt->bindValue(":displayname", $displayname, PDO::PARAM_STR);
		$stmt->bindValue(":webauthnkeys", '', PDO::PARAM_STR);
		$stmt->bindValue(":lastlogin_on", date("Y-m-d H:i:s"), PDO::PARAM_STR);
		$stmt->bindValue(":created_on", date("Y-m-d H:i:s"), PDO::PARAM_STR);
		$stmt->execute();
		$id = $pdo->lastInsertId();
		$pdo->commit();

		return (object) [
			'id' => $id,
			'username' => $username,
			'displayname' => $displayname,
			'webauthnkeys' => ''
		];
	}

	return false;
}
function addFailedLogAttempt(PDO $pdo, $username = false, $reason = "") {

	if ($username) {
		$ip = $_SERVER['REMOTE_ADDR'];
		$agent = new CI_User_agent();

		$pdo->beginTransaction();
		$stmt = $pdo->prepare("INSERT INTO login_attempts (username, reason, ip, agent, ts, created_on) VALUES (:username, :reason, :ip, :agent, :ts, :created_on)");
		$stmt->bindValue(":username", $username, PDO::PARAM_STR);
		$stmt->bindValue(":reason", $reason, PDO::PARAM_STR);
		$stmt->bindValue(":ip", $ip, PDO::PARAM_STR);
		$stmt->bindValue(":agent", $agent->agent_string(), PDO::PARAM_STR);
		$stmt->bindValue(":ts", time(), PDO::PARAM_INT);
		$stmt->bindValue(":created_on", date("Y-m-d H:i:s"), PDO::PARAM_STR);
		$stmt->execute();
		$pdo->commit();
		return true;
	}
	return false;
}
function setUserSuccessfulLogin(PDO $pdo, $user = false) {

	if ($user) {
		$pdo->beginTransaction();
		$stmt = $pdo->prepare("UPDATE users SET failed_login_attempts=:failed_login_attempts, failed_login_ts=:failed_login_ts, lastlogin_on=:lastlogin_on WHERE id=:id");
		$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
		$stmt->bindValue(":failed_login_attempts", 0, PDO::PARAM_INT);
		$stmt->bindValue(":failed_login_ts", time(), PDO::PARAM_INT);
		$stmt->bindValue(":lastlogin_on",  date("Y-m-d H:i:s"), PDO::PARAM_STR);
		$stmt->execute();
		$count = $stmt->rowCount();
		$pdo->commit();
		if ($count > 0) {
			return true;
		}
	}
	return false;
}

function setUserFailedLogin(PDO $pdo, $user = false) {

	if ($user) {
		$pdo->beginTransaction();
		$stmt = $pdo->prepare("UPDATE users SET failed_login_attempts=:failed_login_attempts , failed_login_ts=:failed_login_ts WHERE id=:id");
		$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
		$stmt->bindValue(":failed_login_attempts", ($user->failed_login_attempts + 1), PDO::PARAM_INT);
		$stmt->bindValue(":failed_login_ts", time(), PDO::PARAM_INT);
		$stmt->execute();
		$count = $stmt->rowCount();
		$pdo->commit();
		if ($count > 0) {
			return true;
		}
	}
	return true;
}

function setKey(PDO $pdo, $user = false, $webauthnkeys = false) {

	if ($user && $webauthnkeys) {
		$pdo->beginTransaction();
		$stmt = $pdo->prepare("UPDATE users SET webauthnkeys=:webauthnkeys WHERE id=:id");
		$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
		$stmt->bindValue(":webauthnkeys", $webauthnkeys , PDO::PARAM_STR);
		$stmt->execute();
		$count = $stmt->rowCount();
		$pdo->commit();
		if ($count > 0) {
			return true;
		}
	}
	return false;
}

function removeKey(PDO $pdo, $user = false, $keyhash = false) {

	if ($user && $keyhash) {
		$keys = json_decode($user->webauthnkeys, true);
		$webauthnkeys = json_encode( removeElementWithValue($keys, "keyhash", $keyhash) );

		$pdo->beginTransaction();
		$stmt = $pdo->prepare("UPDATE users SET webauthnkeys=:webauthnkeys WHERE id=:id");
		$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
		$stmt->bindValue(":webauthnkeys", $webauthnkeys , PDO::PARAM_STR);
		$stmt->execute();
		$count = $stmt->rowCount();
		$pdo->commit();
		if ($count > 0) {
			return true;
		}
	}

	return false;
}

function createToken(PDO $pdo, $userid = false) {

	if ($userid) {
		$str = $userid . time() . bin2hex(random_bytes(10));
		$selector = base64_encode(hash('sha384', $str));
		$validator = bin2hex(random_bytes(20));
		$hashedvalidator = hash('sha384', $validator, false);
		$expires = time() + 30*24*60*60;
		$pdo->beginTransaction();
		$stmt = $pdo->prepare("INSERT INTO auth_tokens (selector, hashedvalidator, userid, expires, created_on) VALUES (:selector, :hashedvalidator, :userid, :expires, :created_on)");
		$stmt->bindValue(":selector", $selector, PDO::PARAM_STR);
		$stmt->bindValue(":hashedvalidator", $hashedvalidator , PDO::PARAM_STR);
		$stmt->bindValue(":userid", $userid, PDO::PARAM_INT);
		$stmt->bindValue(":expires", $expires, PDO::PARAM_INT);
		$stmt->bindValue(":created_on", date("Y-m-d H:i:s") ,PDO::PARAM_STR);
		$stmt->execute();
		$pdo->commit();

		return $selector .":". $validator;
	}

	return false;
}

function checkToken(PDO $pdo, $token = false) {

	if ($token && strpos($token, ':') !== false) {
		list($selector, $validator) = explode(":", $token);
		$hashedvalidator = hash('sha384', $validator, false);

		$stmt = $pdo->prepare("SELECT * FROM auth_tokens WHERE selector=:selector AND hashedvalidator=:hashedvalidator LIMIT 1");
		$stmt->bindValue(":selector", $selector, PDO::PARAM_STR);
		$stmt->bindValue(":hashedvalidator", $hashedvalidator, PDO::PARAM_STR);
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($row) {
			if ($row['expires'] > time()){
				return (int) $row['userid'];	
			}
		} else {
			return false;
		}
	}

	return false;
}



function oops($s = "", $code = 400){

	if (is_array($s)) {
		$json = [
		    'method' => ACTION,
		    'error'=> $s
		];
	} else {
		$json = [
		    'method' => ACTION,
		    'error'=> [
		    	'code' => $code,
		        'message' => $s,
		    ]
		];

	}

	header('Content-type: application/json');
	http_response_code($code);
	echo json_encode($json);
	exit;
}

function logger($title = "", $log_msg = "") {

    $log_file_data = 'log_' . date('Y-m-d') . '.log';
    if (SYS_DEBUG) {
		file_put_contents($log_file_data, "[". date("Y-m-d H:i:s") ."]	". $title . "	". $log_msg . "\n", FILE_APPEND);
    }
}

function removeElementWithValue($array, $key, $value){

    foreach($array as $subKey => $subArray){
    	if($subArray[$key] == $value) {
    		unset($array[$subKey]);
    	}
    }

	return $array;
}

// ############################################################################














session_start();

$_SESSION['logged'] = $_SESSION['logged'] ?? false;
$_SESSION['userid'] = $_SESSION['userid'] ?? false;
$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] ?? 0;
$_SESSION['attempt_ts'] = $_SESSION['attempt_ts'] ?? 0;

$pdo = EstablishDBCon();

// $backupFile = '/home/domain/private_data/webauthn_users.sqlite3';
/* A post is an ajax request, otherwise display the page */
if (! empty($_POST['action'])) {
	define('ACTION', $_POST['action']);

	try {
		$webauthn = new davidearl\webauthn\WebAuthn($_SERVER['HTTP_HOST']);
		switch($_POST['action']){

/***
 *    ██████╗ ███████╗ ██████╗ ██╗███████╗████████╗███████╗██████╗       ██╗   ██╗███████╗███████╗██████╗ 
 *    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗      ██║   ██║██╔════╝██╔════╝██╔══██╗
 *    ██████╔╝█████╗  ██║  ███╗██║███████╗   ██║   █████╗  ██████╔╝█████╗██║   ██║███████╗█████╗  ██████╔╝
 *    ██╔══██╗██╔══╝  ██║   ██║██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════╝██║   ██║╚════██║██╔══╝  ██╔══██╗
 *    ██║  ██║███████╗╚██████╔╝██║███████║   ██║   ███████╗██║  ██║      ╚██████╔╝███████║███████╗██║  ██║
 *    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
 *                                                                                                        
 */

			case "register-user":
				$username = $_POST['username'] ?? '';
				$password = $_POST['password'] ?? '';

				if (empty($username)) {
					oops("username is empty ");
				}
				if (empty($password) OR strlen($password) < 2) {
					oops("password is empty or too short (2 chars) ");
				}
				$row = getUserByName($pdo, $username);
				if ($row) {
					oops("user <b>{$username}</b> already exists");
				}				
				$hashedPassword = password_hash(
					base64_encode(
						hash('sha384', $password, true)
					),
					PASSWORD_DEFAULT
				);
				$user = addUser($pdo, $username, $hashedPassword);
				$_SESSION['logged'] = true;
				$_SESSION['username'] = $user->username;
				$_SESSION['userid'] = $user->id;
				$json = [
				    'method' => 'register-user',
				    'data'=> [
				        'message' => "Registration successful <br> Welcome <b>${username}</b>",
				    	'username' => $user->username,
				    ]
				];
				break;


/***
 *    ██╗      ██████╗  ██████╗ ██╗███╗   ██╗       ██████╗██╗  ██╗ █████╗ ██╗     ██╗     ███████╗███╗   ██╗ ██████╗ ███████╗
 *    ██║     ██╔═══██╗██╔════╝ ██║████╗  ██║      ██╔════╝██║  ██║██╔══██╗██║     ██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝
 *    ██║     ██║   ██║██║  ███╗██║██╔██╗ ██║█████╗██║     ███████║███████║██║     ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  
 *    ██║     ██║   ██║██║   ██║██║██║╚██╗██║╚════╝██║     ██╔══██║██╔══██║██║     ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  
 *    ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║      ╚██████╗██║  ██║██║  ██║███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗
 *    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
 *                                                                                                                            
 */

			case "login-challenge":
				/* initiate the login */
				$username = $_POST['username'] ?? '';
				$password = $_POST['password'] ?? '';

				if (empty($username)) {
					oops("username is empty ");
				}
				if (empty($password) OR strlen($password) < 2) {
					oops("password is empty or too short (2 chars) ");
				}

				if ($_SESSION['attempt_failed'] > 60) {
					addFailedLogAttempt($pdo, $username, "login: blocked: too many attempts");
					oops("too many tries. Access denied", 403);
				}
				$delay_in_seconds = pow(3, $_SESSION['attempt_failed']);
				if ( 
					($_SESSION['attempt_ts'] + $delay_in_seconds) > time()
				) {
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();

					addFailedLogAttempt($pdo, $username, "login: spamming");
					oops([
						'message' => "Stop spamming!<br> You need to wait <b>".  gmdate("H\h i\m s\s", $delay_in_seconds) . "</b> before next try.",
						'code' => 400,
						'login_delay' => $delay_in_seconds
					]);
				}

				// CHECK username
				$user = getUserByName($pdo, $username);
				if (! $user) {
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();
					addFailedLogAttempt($pdo, $username, "username: not found");

					oops("Login failed. Please check your username and password", 401);
				}
				// Check delay for failed attemps
				if ($user->failed_login_attempts > 0) {
					$delay_in_seconds = pow(3, $user->failed_login_attempts);
					if (
						( $user->failed_login_ts + $delay_in_seconds) > time()
					) {
						$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
						$_SESSION['attempt_ts'] = time();

						setUserFailedLogin($pdo, $user);
						oops("Stop spamming!<br> You need to wait <b>".  gmdate("H\h i\m s\s", $delay_in_seconds) . "</b> before next try.");
					}
				}

				//  AND password
				if (password_verify(
					    base64_encode(
					    	hash('sha384', $password, true)
					    ),
					    $user->password
					)) { // success :)

					// Key Authentication required?
					$webauthnkeys = json_decode($user->webauthnkeys);
					if (!empty($webauthnkeys)) { // YES
						$_SESSION['attempt_userid'] = $user->id;

						$challenge = $webauthn->prepare_for_login($user->webauthnkeys);
						$json = [
						    'method' => 'login-challenge',
						    'data'=> [
						        'logged' => false,
						        'challenge' => $challenge,
						    ]
						];
					} else  { // NO key required
						$_SESSION['logged'] = true;
						$_SESSION['username'] = $user->username;
						$_SESSION['userid'] = $user->id;
						unset($_SESSION['attempt_failed']);
						unset($_SESSION['attempt_ts']);
						setcookie("logged", true, 0, "/");
						setUserSuccessfulLogin($pdo, $user);

						if ($_POST['rememberme']) {							
							$r_token = createToken($pdo, $user->id);
							setcookie("r_token", $r_token, time()+(30*24*60*60), "/");
						}
						$json = [
						    'method' => 'login-challenge',
						    'data'=> [
						        'logged' => true,
						        'challenge' => false,
						        'username' => $user->username,
						    ]
						];
					}
				} else { // password_verify() failed :(
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();
					setUserFailedLogin($pdo, $user);
					addFailedLogAttempt($pdo, $user->username, "password: wrong");

					oops("Login failed. Please check your username and password", 401);
				}
				break;

/***
 *    ██╗      ██████╗  ██████╗ ██╗███╗   ██╗       █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗██╗ ██████╗ █████╗ ████████╗███████╗
 *    ██║     ██╔═══██╗██╔════╝ ██║████╗  ██║      ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
 *    ██║     ██║   ██║██║  ███╗██║██╔██╗ ██║█████╗███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ██║██║     ███████║   ██║   █████╗  
 *    ██║     ██║   ██║██║   ██║██║██║╚██╗██║╚════╝██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     ██╔══██║   ██║   ██╔══╝  
 *    ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║      ██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ██║╚██████╗██║  ██║   ██║   ███████╗
 *    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
 *                                                                                                                                                  
 */

			case "login-authenticate":
				/* authenticate the login */
				if (empty($_SESSION['attempt_userid'])) {
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;

					oops('login attempt failed. Initical credentials failed.');
				}
				$attempt_userid = $_SESSION['attempt_userid'];
				$attempt_keyinfo = $_POST['keyinfo'];
				$user = getUserById($pdo, $attempt_userid);
				if (! $webauthn->authenticate($attempt_keyinfo, $user->webauthnkeys)) {
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();

					oops('Key invalid', 401);
				} else { // Key is OK
					$_SESSION['logged'] = true;
					$_SESSION['userid'] = $user->id;
					$_SESSION['username'] = $user->username;
					unset($_SESSION['attempt_failed']);
					unset($_SESSION['attempt_ts']);
					setcookie("logged", true, 0, "/");
					setUserSuccessfulLogin($pdo, $user);

					if ($_POST['rememberme']) {
						$r_token = createToken($pdo, $user->id);
						setcookie("r_token", $r_token, time()+(30*24*60*60), "/");
					}
					$json = [
					    'method' => 'login-challenge',
					    'data'=> [
					        'logged' => true,
					        'message' => 'authenticated',
					    ]
					];
				}
				break;















/***
 *    ██████╗ ███████╗ ██████╗ ██╗███████╗████████╗███████╗██████╗        ██████╗██╗  ██╗ █████╗ ██╗     ██╗     ███████╗███╗   ██╗ ██████╗ ███████╗
 *    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗      ██╔════╝██║  ██║██╔══██╗██║     ██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝
 *    ██████╔╝█████╗  ██║  ███╗██║███████╗   ██║   █████╗  ██████╔╝█████╗██║     ███████║███████║██║     ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  
 *    ██╔══██╗██╔══╝  ██║   ██║██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════╝██║     ██╔══██║██╔══██║██║     ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  
 *    ██║  ██║███████╗╚██████╔╝██║███████║   ██║   ███████╗██║  ██║      ╚██████╗██║  ██║██║  ██║███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗
 *    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
 *                                                                                                                                                  
 */

			case "register-challenge":
				if(!$_SESSION['logged'] OR !$_SESSION['userid']) {
					oops("Please login first", 401);
				}
				if($_POST['keyname'] =="") {
					oops("Key need a name");
				}
				$user = getUserById($pdo, $_SESSION['userid']);
				$json = [
				    'method' => 'register-challenge',
				    'code' => 200,
				    'data'=> [
				    	'keyname' => $_POST['keyname'],
				        'challenge' => $webauthn->prepare_challenge_for_registration($user->username, $user->id)
				    ]
				];
				break;

/***
 *    ██████╗ ███████╗ ██████╗ ██╗███████╗████████╗███████╗██████╗       ██╗  ██╗███████╗██╗   ██╗
 *    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗      ██║ ██╔╝██╔════╝╚██╗ ██╔╝
 *    ██████╔╝█████╗  ██║  ███╗██║███████╗   ██║   █████╗  ██████╔╝█████╗█████╔╝ █████╗   ╚████╔╝ 
 *    ██╔══██╗██╔══╝  ██║   ██║██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════╝██╔═██╗ ██╔══╝    ╚██╔╝  
 *    ██║  ██║███████╗╚██████╔╝██║███████║   ██║   ███████╗██║  ██║      ██║  ██╗███████╗   ██║   
 *    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚══════╝   ╚═╝   
 *                                                                                                
 */

			case "register-key":
				/* complete the registration */
				if(!$_SESSION['logged'] OR !$_SESSION['userid']) {
					oops("Please login first", 401);
				}
				$keyname = $_POST['keyname'] ?? '';
				if(!$keyname) {
					oops("Key need a name");
				}
				$keyinfo = $_POST['keyinfo'] ?? '';
				if(!$keyinfo) {
					oops("keyinfo is missing");
				}
				$user = getUserById($pdo, $_SESSION['userid']);
				if (!$user) {
					oops('user not found');
				}
				// inject key name into keyinfo JSON
				$keyinfo_decoded = json_decode($keyinfo);
				$keyinfo_decoded->keyname = $keyname;
				$keyinfo = json_encode($keyinfo_decoded);
				$webauthnkeys = $webauthn->register($keyinfo, $user->webauthnkeys);
				setKey($pdo, $user, $webauthnkeys);
				$json = [
				    'method' => 'register-key',
				    'data'=> [
				        'message' => 'Success: Key registered'
				    ]
				];
				break;















/***
 *    ██╗  ██╗███████╗██╗   ██╗      ██╗     ██╗███████╗████████╗
 *    ██║ ██╔╝██╔════╝╚██╗ ██╔╝      ██║     ██║██╔════╝╚══██╔══╝
 *    █████╔╝ █████╗   ╚████╔╝ █████╗██║     ██║███████╗   ██║   
 *    ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════╝██║     ██║╚════██║   ██║   
 *    ██║  ██╗███████╗   ██║         ███████╗██║███████║   ██║   
 *    ╚═╝  ╚═╝╚══════╝   ╚═╝         ╚══════╝╚═╝╚══════╝   ╚═╝   
 *                                                               
 */

			case "key-list":
				if(!$_SESSION['logged'] OR !$_SESSION['userid']) {
					oops("Please login first", 401);
				}
				$user = getUserById($pdo, $_SESSION['userid']);
				$json = [
				    'method' => 'key-list',
				    'data'=> [
				        'keys' => json_decode($user->webauthnkeys)
				    ]
				];
				break;

/***
 *    ██╗  ██╗███████╗██╗   ██╗      ██████╗ ███████╗██╗     ███████╗████████╗███████╗
 *    ██║ ██╔╝██╔════╝╚██╗ ██╔╝      ██╔══██╗██╔════╝██║     ██╔════╝╚══██╔══╝██╔════╝
 *    █████╔╝ █████╗   ╚████╔╝ █████╗██║  ██║█████╗  ██║     █████╗     ██║   █████╗  
 *    ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════╝██║  ██║██╔══╝  ██║     ██╔══╝     ██║   ██╔══╝  
 *    ██║  ██╗███████╗   ██║         ██████╔╝███████╗███████╗███████╗   ██║   ███████╗
 *    ╚═╝  ╚═╝╚══════╝   ╚═╝         ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝   ╚══════╝
 *                                                                                    
 */

			case "key-delete":
				if(!$_SESSION['logged'] OR !$_SESSION['userid']) {
					oops("Please login first", 401);
				}
				$keyhash = $_POST['keyhash'];
				$user = getUserById($pdo, $_SESSION['userid']);
				removeKey($pdo, $user, $keyhash);				
				$json = [
				    'method' => 'key-delete',
				    'data'=> [
				        'message' => "Key removed"
				    ]
				];
				break;

/***
 *     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗      ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗
 *    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝      ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║
 *    ██║     ███████║█████╗  ██║     █████╔╝ █████╗   ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║
 *    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ╚════╝   ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║
 *    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗         ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║
 *     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝         ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
 *                                                                                              
 */

			case "check-token":
				$token = urldecode($_COOKIE['r_token']);
				$userid = checkToken($pdo, $token);
				if ($userid) {
					$user = getUserById($pdo, $userid);	
					if ($user) {
						$_SESSION['logged'] = true;
						$_SESSION['userid'] = $user->id;
						setcookie("logged", true, 0, "/");
						
						$json = [
						    'method' => 'check-token',
						    'data'=> [
						        'message' => "Welcome back " . $user->displayname
						    ]
						];
					} else {
						unset($_COOKIE['r_token']);
						setcookie('r_token', "", time()-3600, '/');

						oops("Invalid Cookie");
					}
				} else {
					unset($_COOKIE['r_token']);
					setcookie('r_token', "", time()-3600, '/');

					oops("Invalid Cookie");
				}
				break;















/***
 *    ██╗      ██████╗  ██████╗  ██████╗ ██╗   ██╗████████╗
 *    ██║     ██╔═══██╗██╔════╝ ██╔═══██╗██║   ██║╚══██╔══╝
 *    ██║     ██║   ██║██║  ███╗██║   ██║██║   ██║   ██║   
 *    ██║     ██║   ██║██║   ██║██║   ██║██║   ██║   ██║   
 *    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝   ██║   
 *    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   
 *                                                         
 */

			case "logout":
				$_SESSION['logged'] = false;
				unset($_SESSION['userid']);
				setcookie('logged', "", time()-3600, '/');
				setcookie('r_token', "", time()-3600, '/');
				$json = [
				    'method' => 'logout',
				    'data'=> [
				        'message' => "You logged out."
				    ]
				];
				break;

/***
 *    ██████╗ ███████╗███████╗ █████╗ ██╗   ██╗██╗     ████████╗
 *    ██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██║     ╚══██╔══╝
 *    ██║  ██║█████╗  █████╗  ███████║██║   ██║██║        ██║   
 *    ██║  ██║██╔══╝  ██╔══╝  ██╔══██║██║   ██║██║        ██║   
 *    ██████╔╝███████╗██║     ██║  ██║╚██████╔╝███████╗   ██║   
 *    ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
 *                                                              
 */
			default:
				oops("unrecognized action", 405);
				break;
		}    
	} catch(Exception $ex) {
		logger("Exception: ". json_encode($ex) );
		oops($ex->getMessage());
	}
	$pdo = null;

	header('Content-type: application/json');
	echo json_encode($json);
	exit;
}

