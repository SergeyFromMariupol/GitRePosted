<?php

declare(strict_types=1);

require dirname(__DIR__) . '/lib/Wizard.php';

use GitRePostedInstaller\Wizard;

function expectWizard(mixed $expected, mixed $actual): void
{
    if ($expected !== $actual) throw new RuntimeException('Wizard assertion failed: '.var_export($expected,true).' != '.var_export($actual,true));
}

function fixtureWizard(): object
{
    $f=new stdClass();
    $f->now=1770000000;
    $f->public=['base_url'=>'https://203.0.113.10','host'=>'203.0.113.10','public_ip'=>'203.0.113.10','tls_ready'=>true,'installed'=>false,'version'=>'fixture'];
    $f->access=['code_hash'=>password_hash('fixture-enrollment-code',PASSWORD_DEFAULT),'expires_at'=>$f->now+600];
    $f->session=[]; $f->calls=[]; $f->rates=[]; $f->rotations=0; $f->denied=false; $f->used=false; $f->override=null;
    $f->server=['HTTPS'=>'on','HTTP_HOST'=>'203.0.113.10','HTTP_ORIGIN'=>'https://203.0.113.10','REMOTE_ADDR'=>'198.51.100.20','CONTENT_TYPE'=>'application/json','HTTP_SEC_FETCH_SITE'=>'same-origin'];
    $f->controller=new Wizard(
        static fn(string $name):array=>$name==='public.json'?$f->public:$f->access,
        static function(string $action,array $payload)use($f):array{
            $f->calls[]=['action'=>$action,'payload'=>$payload];
            if(is_callable($f->override)) return ($f->override)($action,$payload);
            if($action==='enroll') {
                if($f->used) return ['ok'=>false,'error'=>['code'=>'code_used','message'=>'private broker text']];
                $f->used=true;
                return ['ok'=>true,'result'=>['enrolled'=>true]];
            }
            if($action==='check_bot') return ['ok'=>true,'result'=>['identity'=>['id'=>123456,'username'=>'fixture_bot','name'=>'Fixture bot'],
                'existing_urls'=>['https://old.invalid/webhooks/telegram'],'token'=>$payload['token'],'raw'=>'must not leak']];
            return ['ok'=>true,'result'=>['job'=>['id'=>'fixture-job','type'=>$action==='host'?'host':'install','status'=>$action==='status'?'idle':'running',
                'steps'=>[['id'=>'configure','title'=>'Настройка','status'=>'pending']],'secret'=>'must not leak']]];
        },
        static function(string $scope,string $identity,int $limit,int $seconds,int $now)use($f):bool{
            $f->rates[]=compact('scope','identity','limit','seconds','now');
            return !$f->denied;
        }, $f->session,
        static fn():int=>$f->now,
        static function()use($f):bool{$f->rotations++;return true;}
    );
    return $f;
}

function requestWizard(object $f,string $action,array $payload=[],?array $server=null,string $method='POST'):array
{
    $server=$server??$f->server;
    if(isset($f->session['csrf'])) $server['HTTP_X_CSRF_TOKEN']=$server['HTTP_X_CSRF_TOKEN']??$f->session['csrf'];
    return $f->controller->handle($method,$action,$server,json_encode((object)$payload,JSON_THROW_ON_ERROR));
}

function loginWizard(object $f):void
{
    expectWizard(200,requestWizard($f,'login',['code'=>'fixture-enrollment-code'])['status']);
}

function settingsWizard():array
{
    return ['admin'=>['username'=>'admin','password'=>'fixture-password-123','password_confirm'=>'fixture-password-123'],
        'telegram'=>['enabled'=>false,'token'=>'discarded disabled token','takeover'=>false],
        'max'=>['enabled'=>false,'token'=>'discarded disabled token','takeover'=>false],
        'timezone'=>'Europe/Moscow','support_username'=>'','hcaptcha'=>['enabled'=>false]];
}

$tests=[];
$tests['public status exposes no credentials csrf or broker call']=static function():void{
    $f=fixtureWizard();$r=requestWizard($f,'status',method:'GET');
    expectWizard(200,$r['status']);expectWizard(false,$r['body']['result']['authenticated']);
    expectWizard(false,isset($r['body']['result']['csrf']));expectWizard([],$f->calls);
};
$tests['login consumes code once rotates session and stores no credentials']=static function():void{
    $f=fixtureWizard();$f->session=['untrusted'=>'old fixation'];loginWizard($f);
    expectWizard(1,$f->rotations);expectWizard('enroll',$f->calls[0]['action']);
    expectWizard(['authenticated','created_at','last_activity','csrf'],array_keys($f->session));
    expectWizard(false,str_contains(json_encode($f->session),'fixture-enrollment-code'));
    expectWizard(409,requestWizard($f,'login',['code'=>'fixture-enrollment-code'])['status']);
};
$tests['bad or expired code never reaches root broker']=static function():void{
    foreach(['bad','expired']as$case){$f=fixtureWizard();if($case==='expired')$f->access['expires_at']=$f->now-1;
        expectWizard(401,requestWizard($f,'login',['code'=>$case==='bad'?'incorrect-code':'fixture-enrollment-code'])['status']);expectWizard([],$f->calls);}
};
$tests['http and forwarded https headers cannot enroll']=static function():void{
    $f=fixtureWizard();$server=$f->server;unset($server['HTTPS']);$server['HTTP_X_FORWARDED_PROTO']='https';$server['HTTP_FORWARDED']='proto=https';
    expectWizard(403,requestWizard($f,'login',['code'=>'fixture-enrollment-code'],$server)['status']);expectWizard([],$f->calls);
};
$tests['TLS not ready prevents secrets even on HTTPS SAPI']=static function():void{
    $f=fixtureWizard();$f->public['tls_ready']=false;
    expectWizard(403,requestWizard($f,'login',['code'=>'fixture-enrollment-code'])['status']);expectWizard([],$f->calls);
};
$tests['host origin fetch metadata and ports cannot bypass same origin']=static function():void{
    foreach(['HTTP_HOST'=>'evil.invalid','HTTP_ORIGIN'=>'https://evil.invalid','HTTP_SEC_FETCH_SITE'=>'cross-site']as$key=>$value){
        $f=fixtureWizard();$server=$f->server;$server[$key]=$value;
        expectWizard(403,requestWizard($f,'login',['code'=>'fixture-enrollment-code'],$server)['status']);expectWizard([],$f->calls);
    }
    foreach(['203.0.113.10:80','203.0.113.10@evil.invalid','203.0.113.10\\evil','203.0.113.10%00']as$host){
        $f=fixtureWizard();$server=$f->server;$server['HTTP_HOST']=$host;
        expectWizard(403,requestWizard($f,'status',server:$server,method:'GET')['status']);
    }
};
$tests['missing Origin is rejected including login']=static function():void{
    $f=fixtureWizard();$server=$f->server;unset($server['HTTP_ORIGIN']);
    expectWizard(403,requestWizard($f,'login',['code'=>'fixture-enrollment-code'],$server)['status']);
};
$tests['csrf protects every authenticated mutation']=static function():void{
    foreach(['logout','check_bot','start','retry','host']as$action){$f=fixtureWizard();loginWizard($f);$f->calls=[];$server=$f->server;$server['HTTP_X_CSRF_TOKEN']=str_repeat('0',64);
        expectWizard(403,requestWizard($f,$action,server:$server)['status']);expectWizard([],$f->calls);}
};
$tests['expired session cannot mutate and logout rotates']=static function():void{
    $f=fixtureWizard();loginWizard($f);$f->now+=1801;
    expectWizard(401,requestWizard($f,'retry',['job_id'=>'fixture-job'])['status']);expectWizard([],$f->session);
    $f=fixtureWizard();loginWizard($f);expectWizard(200,requestWizard($f,'logout')['status']);expectWizard([],$f->session);expectWizard(2,$f->rotations);
};
$tests['installed marker locks every mutation including enrollment']=static function():void{
    foreach(['login','logout','check_bot','start','retry','host']as$action){$f=fixtureWizard();$f->public['installed']=true;
        expectWizard(410,requestWizard($f,$action)['status']);expectWizard([],$f->calls);}
};
$tests['rate limiting uses remote peer and fails closed']=static function():void{
    $f=fixtureWizard();$f->denied=true;$server=$f->server;$server['HTTP_X_FORWARDED_FOR']='127.0.0.1';
    expectWizard(429,requestWizard($f,'login',['code'=>'fixture-enrollment-code'],$server)['status']);
    expectWizard('198.51.100.20',$f->rates[0]['identity']);expectWizard([],$f->calls);
};
$tests['bad JSON content type unknown fields and body size reject before broker']=static function():void{
    $f=fixtureWizard();$server=$f->server;$server['CONTENT_TYPE']='text/plain';
    expectWizard(415,requestWizard($f,'login',['code'=>'fixture-enrollment-code'],$server)['status']);
    expectWizard(400,$f->controller->handle('POST','login',$f->server,'{')['status']);
    expectWizard(400,$f->controller->handle('POST','login',$f->server,'[]')['status']);
    expectWizard(413,$f->controller->handle('POST','login',$f->server,str_repeat('x',32769))['status']);
    expectWizard(400,requestWizard($f,'login',['code'=>'fixture-enrollment-code','path'=>'/etc/passwd'])['status']);expectWizard([],$f->calls);
};
$tests['admin only install strips disabled secrets and leaves support empty']=static function():void{
    $f=fixtureWizard();loginWizard($f);$f->calls=[];$r=requestWizard($f,'start',['settings'=>settingsWizard()]);
    expectWizard(200,$r['status']);$settings=$f->calls[0]['payload']['settings'];
    expectWizard('',$settings['telegram']['token']);expectWizard('',$settings['max']['token']);expectWizard('',$settings['support_username']);
    expectWizard(false,str_contains(json_encode($r),'fixture-password'));expectWizard(false,str_contains(json_encode($f->session),'fixture-password'));
};
$tests['strict settings reject bad types password mismatch timezone and injected fields']=static function():void{
    $mutations=[
        static function(array&$s):void{$s['telegram']['enabled']='false';},
        static function(array&$s):void{$s['admin']['password_confirm']='different-password';},
        static function(array&$s):void{$s['admin']['password']=$s['admin']['password_confirm']=str_repeat('x',73);},
        static function(array&$s):void{$s['admin']['username']='../../root';},
        static function(array&$s):void{$s['timezone']='Invalid/Timezone';},
        static function(array&$s):void{$s['app_root']='/etc';},
        static function(array&$s):void{$s['mtproto']=['enabled'=>true,'api_id'=>123,'api_hash'=>str_repeat('a',32)];},
        static function(array&$s):void{$s['hcaptcha']=['enabled'=>true,'sitekey'=>'invalid','secret'=>'invalid'];},
    ];
    foreach($mutations as$mutate){$f=fixtureWizard();loginWizard($f);$f->calls=[];$s=settingsWizard();$mutate($s);
        expectWizard(400,requestWizard($f,'start',['settings'=>$s])['status']);expectWizard([],$f->calls);}
};
$tests['selected Telegram and MAX normalize without credential echo']=static function():void{
    $f=fixtureWizard();loginWizard($f);$s=settingsWizard();$s['telegram']=['enabled'=>true,'token'=>'123456:'.str_repeat('a',35),'takeover'=>true];
    $s['max']=['enabled'=>true,'token'=>str_repeat('m',40),'takeover'=>false];
    expectWizard(200,requestWizard($f,'start',['settings'=>$s])['status']);expectWizard(true,$f->calls[1]['payload']['settings']['telegram']['takeover']);
};
$tests['four platform modes preserve selection strip skipped tokens and keep secrets out of responses']=static function():void{
    foreach([[false,false],[true,false],[false,true],[true,true]]as[$telegram,$max]){
        $f=fixtureWizard();loginWizard($f);$s=settingsWizard();$s['timezone']='UTC';
        foreach(['telegram'=>$telegram,'max'=>$max]as$platform=>$enabled){
            $s[$platform]=['enabled'=>$enabled,'token'=>$platform==='telegram'?'123456:'.str_repeat('a',35):str_repeat('m',40),'takeover'=>false];
        }
        $r=requestWizard($f,'start',['settings'=>$s]);expectWizard(200,$r['status']);
        $forwarded=$f->calls[1]['payload']['settings'];expectWizard('UTC',$forwarded['timezone']);
        foreach(['telegram'=>$telegram,'max'=>$max]as$platform=>$enabled){
            expectWizard($enabled,$forwarded[$platform]['enabled']);
            expectWizard($enabled?$s[$platform]['token']:'',$forwarded[$platform]['token']);
            expectWizard(false,$forwarded[$platform]['takeover']);
        }
        expectWizard(false,str_contains(json_encode($r),'fixture-password'));
        expectWizard(false,str_contains(json_encode($r),str_repeat('a',35)));
        expectWizard(false,str_contains(json_encode($r),str_repeat('m',40)));
        expectWizard(false,str_contains(json_encode($f->session),'fixture-password'));
    }
};
$tests['check bot returns only identity and safe URL list']=static function():void{
    $f=fixtureWizard();loginWizard($f);$r=requestWizard($f,'check_bot',['platform'=>'telegram','token'=>'123456:'.str_repeat('a',35)]);
    expectWizard(200,$r['status']);expectWizard(['identity','existing_urls'],array_keys($r['body']['result']));
    expectWizard(false,str_contains(json_encode($r),'must not leak'));expectWizard(false,str_contains(json_encode($r),str_repeat('a',35)));
};
$tests['broker failures expose safe messages rather than stderr secrets']=static function():void{
    $f=fixtureWizard();loginWizard($f);$f->override=static fn():array=>['ok'=>false,'error'=>['code'=>'invalid_token','message'=>'SECRET TOKEN accidental raw stderr']];
    $r=requestWizard($f,'check_bot',['platform'=>'max','token'=>str_repeat('m',40)]);
    expectWizard(409,$r['status']);expectWizard('INVALID_TOKEN',$r['body']['error']['code']);expectWizard(false,str_contains(json_encode($r),'SECRET'));
};
$tests['domain job retains initial origin session and exposes final site separately']=static function():void{
    $f=fixtureWizard();loginWizard($f);$csrf=$f->session['csrf'];
    $r=requestWizard($f,'host',['host'=>'Example.COM','email'=>'owner@example.com']);expectWizard(200,$r['status']);expectWizard('host',$r['body']['result']['job']['type']);
    expectWizard(false,$r['body']['result']['reconnect']);expectWizard($csrf,$f->session['csrf']);
    $f->public['site_url']='https://example.com';$f->public['site_host']='example.com';$f->public['allowed_hosts']=['203.0.113.10','example.com'];
    $r=requestWizard($f,'status',method:'GET');expectWizard('https://203.0.113.10',$r['body']['result']['base_url']);expectWizard('https://example.com/control/',$r['body']['result']['admin_url']);
    $server=$f->server;$server['HTTP_HOST']='example.com';$server['HTTP_ORIGIN']='https://example.com';expectWizard(200,requestWizard($f,'retry',['job_id'=>'fixture-job'],$server)['status']);
    $server['HTTP_ORIGIN']='https://203.0.113.10';expectWizard(403,requestWizard($f,'retry',['job_id'=>'fixture-job'],$server)['status']);
};
$tests['host and retry reject paths commands foreign IP and email injection']=static function():void{
    foreach([['host'=>['host'=>'example.com/path']],['host'=>['host'=>'https://example.com']],['host'=>['host'=>'203.0.113.11']],
        ['host'=>['host'=>'example.com','email'=>"x@example.com\r\nInjected: yes"]],['retry'=>['job_id'=>'../../etc']]]as$case){
        $f=fixtureWizard();loginWizard($f);$f->calls=[];$action=array_key_first($case);
        expectWizard(400,requestWizard($f,$action,$case[$action])['status']);expectWizard([],$f->calls);
    }
};

$tests['fixed project mount scopes setup metadata without weakening host or origin checks']=static function():void{
    $f=fixtureWizard();$f->public['base_url'].='/GitRePosted';$f->public['path_prefix']='/GitRePosted';
    expectWizard('/GitRePosted',Wizard::pathPrefix($f->public));
    $r=requestWizard($f,'status',method:'GET');expectWizard(200,$r['status']);
    expectWizard('/GitRePosted',$r['body']['result']['path_prefix']);
    expectWizard('https://203.0.113.10/GitRePosted/control/',$r['body']['result']['admin_url']);
    loginWizard($f);expectWizard(200,requestWizard($f,'start',['settings'=>settingsWizard()])['status']);
    foreach(['/GitPosted','/GitRePosted/','/other/../GitRePosted','/%47itRePosted']as$path){
        $f->public['base_url']='https://203.0.113.10'.$path;
        expectWizard(403,requestWizard($f,'status',method:'GET')['status']);
    }
    $f->public['base_url']='https://203.0.113.10/GitRePosted';$f->public['path_prefix']='';
    expectWizard(403,requestWizard($f,'status',method:'GET')['status']);
};

$failed=0;
foreach($tests as$name=>$test){try{$test();echo 'PASS '.$name.PHP_EOL;}catch(Throwable$error){$failed++;fwrite(STDERR,'FAIL '.$name.': '.$error->getMessage().PHP_EOL);}}
echo count($tests).' wizard groups; failures='.$failed.PHP_EOL;
exit($failed===0?0:1);
