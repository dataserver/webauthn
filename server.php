<?php
/*
If you put the whole webauthn directory in the www document root and put an index.php in there 
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/
// ASCII TEXT
// http://patorjk.com/software/taag/#p=display&h=0&c=c&f=ANSI%20Shadow&t=SomeThing

define('SYS_DEBUG', false);

include_once('webauthn.php');

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
			"webauthnkeys" TEXT
		)');
		$pdo->exec('CREATE TABLE IF NOT EXISTS "auth_tokens" (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE ,
			"selector" TEXT,
			"hashedvalidator" TEXT,
			"userid" INTEGER,
			"expires" INTEGER
		)');
		$pdo->exec('CREATE INDEX IF NOT EXISTS `username` ON `users` (`username` ASC)');
		$pdo->exec('CREATE INDEX IF NOT EXISTS `selector` ON `auth_tokens` ( `selector` ASC)');
		
    } catch (Exception $e) {
        // Logging here is a good idea
    }
    return $pdo;

}
$pdo = EstablishDBCon();
function logger($title, $log_msg="") {
    $log_file_data = 'log_' . date('d-M-Y') . '.log';
    if (SYS_DEBUG) {
		file_put_contents($log_file_data, "[". date("Y-m-d H:i:s") ."]	". $title . "	". $log_msg . "\n", FILE_APPEND);
    }
}
function removeElementWithValue($array, $key, $value){
     foreach($array as $subKey => $subArray){
          if($subArray[$key] == $value){
               unset($array[$subKey]);
          }
     }
     return $array;
}


function getUserById(PDO $pdo, $id=null) {
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
function getUserByName(PDO $pdo, $username=null) {
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
function addUser(PDO $pdo, $username, $password) {

	$displayname = strtoupper('Mr. ' . $username);

	$pdo->beginTransaction();
	$stmt = $pdo->prepare("INSERT INTO users (username, password, displayname, webauthnkeys) VALUES (:username, :password, :displayname, :webauthnkeys)");
	$stmt->bindValue(":username", $username);
	$stmt->bindValue(":password", $password);
	$stmt->bindValue(":displayname", $displayname);
	$stmt->bindValue(":webauthnkeys", '');
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
function setKey(PDO $pdo, $user, $webauthnkeys) {

	$stmt = $pdo->prepare("UPDATE users SET webauthnkeys=:webauthnkeys WHERE id=:id");
	$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
	$stmt->bindValue(":webauthnkeys", $webauthnkeys , PDO::PARAM_STR);
	$stmt->execute();

	$count = $stmt->rowCount();
	if ($count > 0) {
		return true;
	}
	return false;
}
function removeKey(PDO $pdo, $user, $keyhash) {

	$keys = json_decode($user->webauthnkeys, true);
	$webauthnkeys = json_encode( removeElementWithValue($keys, "keyhash", $keyhash) );

	$stmt = $pdo->prepare("UPDATE users SET webauthnkeys=:webauthnkeys WHERE id=:id");
	$stmt->bindValue(":id", $user->id, PDO::PARAM_INT);
	$stmt->bindValue(":webauthnkeys", $webauthnkeys , PDO::PARAM_STR);
	$stmt->execute();

	$count = $stmt->rowCount();
	if ($count > 0) {
		return true;
	}
	return false;
}



function createToken(PDO $pdo, $userid) {

	$str = $userid . time() . bin2hex(random_bytes(10));
	
	$selector = base64_encode(hash('sha384', $str));
	$validator = bin2hex(random_bytes(20));

	$hashedvalidator = hash('sha384', $validator, false);
	$expires = time() + 30*24*60*60;

	$pdo->beginTransaction();
	$stmt = $pdo->prepare("INSERT INTO auth_tokens (selector, hashedvalidator, userid, expires) VALUES (:selector, :hashedvalidator, :userid, :expires)");
	$stmt->bindValue(":selector", $selector, PDO::PARAM_STR);
	$stmt->bindValue(":hashedvalidator", $hashedvalidator , PDO::PARAM_STR);
	$stmt->bindValue(":userid", $userid, PDO::PARAM_INT);
	$stmt->bindValue(":expires", $expires, PDO::PARAM_INT);
	$stmt->execute();
	$pdo->commit();
	return $selector .":". $validator;
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
function oops($s, $code = 400){

	$json = [
	    'method' => ACTION,
	    'error'=> [
	    	'code' => $code,
	        'message' => $s,
	    ]
	];
	header('Content-type: application/json');
	http_response_code($code);
	echo json_encode($json);
	exit;
}

// ############################################################################
session_name("user_session");
session_start();

$_SESSION['logged'] = isset($_SESSION['logged']) ?: false;
$_SESSION['userid'] = isset($_SESSION['userid']) ?: false;
$_SESSION['attempt_failed'] = isset($_SESSION['attempt_failed']) ?: 0;
$_SESSION['attempt_ts'] = isset($_SESSION['attempt_ts']) ?: 0;


// $backupFile = '/home/domain/private_data/webauthn_users.sqlite3';
/* A post is an ajax request, otherwise display the page */
if (! empty($_POST['action'])) {
	$action = $_POST['action'];
	define('ACTION', $action);
	try {
		$webauthn = new davidearl\webauthn\WebAuthn($_SERVER['HTTP_HOST']);
		switch($action){

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
				$username = ($_POST['username']) ?  $_POST['username'] : '';
				$password = ($_POST['password']) ?  $_POST['password'] : '';

				if (empty($username)) {
					oops("userName is empty ");
				}
				$row = getUserByName($pdo, $username);
				if ($row) {
					oops("user <b>{$username}</b> already exists");
				}				
				if (empty($password) OR strlen($password) < 2) {
					oops("password is empty or too short (2 chars) ");
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
				        'message' => "${username} is registered & logged",
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
				$username = $_POST['username'];
				$password = $_POST['password'];

				if ($_SESSION['attempt_failed'] > 6) {
					http_response_code(403);
					echo ("too many tries. Access denied");
					exit;
				}
				$last_attempt_in_sec = time() - $_SESSION['attempt_ts'];
				if ( $last_attempt_in_sec < (5 * $_SESSION['attempt_failed']) )  { // 5 sec * each try
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();
					oops("Stop spamming!<br> You need to wait ". (5 * $_SESSION['attempt_failed']) . " seconds before next try.");
				}
				$user = getUserByName($pdo, $username);
				//  AND password
				if (password_verify(
					    base64_encode(
					    	hash('sha384', $password, true)
					    ),
					    $user->password
					)) { // success :)

					$webauthnkeys = json_decode($user->webauthnkeys);
					// Key Authentication required?
					if (!empty($webauthnkeys)) { // YES
						$challenge = $webauthn->prepare_for_login($user->webauthnkeys);
						$_SESSION['attempt_userid'] = $user->id;
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
						if ($_POST['rememberme']) {							
							$r_token = createToken($pdo, $user->id);
							setcookie("r_token", $r_token, time()+(30*24*60*60), "/");
						}
						$json = [
						    'method' => 'login-challenge',
						    'data'=> [
						        'logged' => true,
						        'challenge' => false,
						    ]
						];
					}
				} else { // password_verify() failed :(
					$_SESSION['attempt_failed'] = $_SESSION['attempt_failed'] + 1;
					$_SESSION['attempt_ts'] = time();
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
					oops('login attempt failed. Initical credentials failed.');
				}
				$attempt_userid = $_SESSION['attempt_userid'];
				$attempt_keyinfo = $_POST['keyinfo'];
				$user = getUserById($pdo, $attempt_userid);
				if (! $webauthn->authenticate($attempt_keyinfo, $user->webauthnkeys)) {
					oops('Key invalid', 401);
				} else { // Key is OK
					$_SESSION['logged'] = true;
					$_SESSION['userid'] = $user->id;
					$_SESSION['username'] = $user->username;
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
				if(!$_SESSION['logged']) {
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
				$keyname = $_POST['keyname'];
				if(!$keyname) {
					oops("Key need a name");
				}
				$keyinfo = $_POST['keyinfo'];
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

				// $json['keys'] = json_decode($user->webauthnkeys);
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
				$token = $_COOKIE['r_token'];
				$token = urldecode($token);
				
				$userid = checkToken($pdo, $token);
				$user = getUserById($pdo, $userid);
				if ($user) {
					$_SESSION['logged'] = true;
					$_SESSION['userid'] = $user->id;
					$json = [
					    'method' => 'check-token',
					    'data'=> [
					        'message' => "Welcome back " . $user->displayname
					    ]
					];
				} else {
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
				session_destroy();
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
				oops("unrecognized POST\n", 405);
				break;
		}    

	} catch(Exception $ex) {
		logger("Exception: ". json_encode($ex) );
		oops($ex->getMessage());
	}

	$pdo = null;

	header('Content-type: application/json');
	// http_response_code(200);
	echo json_encode($json);
	exit;
}

