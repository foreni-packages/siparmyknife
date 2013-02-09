#!/usr/bin/perl
#SIP VoIP Protocol Fuzzer
#Created: Blake Cornell

use strict;
#use warnings; LOTS OF WARNING ____ SOLVE THIS AND INCREASE EFFICIENTY

use IO::Select;
use IO::Socket;
use IO::Socket::INET;
use Getopt::Long;
use Pod::Usage;
use Time::HiRes qw( alarm );
use Digest::MD4 qw( md4_hex );
use Digest::MD5 qw( md5_hex );
use Digest::CRC qw( crc32 crc16 );
use HTML::Entities;

my @timeoutDetection = ();
my @md5Requests = ();
my @md4Requests = ();
my @crc32Requests = ();
my @crc16Requests = ();
my $packetCount = 0;
my $socketType='';
my $result = GetOptions('host|h=s' => \(my $host = ''),
      'dport|p=s' => \(my $dport = ''),
      'sport|p=s' => \(my $sport = ''),
      'verbose|v' => \(my $verbose),
      'veryverbose|vv' => \(my $veryVerbose),
      'connection|c' => \(my $connection), #to listen to response or not
      'density|d=s' => \(my $density = 0), #determines how many mutations to use
      'timeout|t=s' => \(my $timeout = .1),
      'count' => \(my $countTests = 0), #counts the number of packets to test
      'md4' => \(my $md4), #can cause timeouts
      'md5' => \(my $md5), #can cause timeouts
      'crc32' => \(my $crc32), #can cause timeouts
      'crc16' => \(my $crc16), #can cause timeouts
      'start=s' => \(my $startPosition), #if set, then start at this position
      'stringFormats' => \(my $stringFormats),
      'stringOverflows' => \(my $stringOverflows),
      'integerFormats' => \(my $integerFormats),
      'injectHeaders' => \(my $injectHeaders),
      'xss' => \(my $xss),
      'sqli' => \(my $sqli),
      'callId' => \(my $callId), #call id is incremented
      'detectVersion' => \(my $detectVersion),
      'getOptions' => \(my $getOptions),
      'help' => \(my $help),
      'proto=s' => \(my $proto),
      'sproto=s' => \(my $sproto),
      'source|s=s' => \(my $source = '')) or pod2usage(2); #sip source IP

print "\n\n";
if($help) { displayHelp(); };
if(!$host) { print "-h, Enter host\n"; exit 1; }
if(!$dport) { $dport = 5060; }
if(!$sport) { 
  $sport = 12345; 
  if($verbose) {
    print "Source Spoof Port default setting: " . $sport . "\n";
  }
}else{
  if($verbose) {
    print "Source Spoof Port user setting: " . $sport . "\n";
  }
}
if(!$connection) { $connection = 1; }else{ $connection = 0; }
if(!$density) { $density = 0; }
if(!$source) { $source = $host; }



$proto = uc($proto);
if(!$proto || ($proto != 'TCP' && $proto != 'UDP')) {
  $proto = "TCP";
  if($verbose) { print "Destination Protocol/Layer 4 Protocol default setting: " . $proto . "\n" };
}else{
  if($verbose) { print "Destination Protocol/Layer 4 Protocol user setting: " . $proto . "\n" };
}


$sproto = uc($sproto);
if(!$sproto || ($sproto != 'TCP' && $sproto != 'UDP')) { 
  $sproto = "TCP";
  if($verbose) { print "Source Protocol/Layer 4 Protocol default setting: " . $sproto . "\n" };
}else{
  if($verbose) { print "Source Protocol/Layer 4 Protocol user setting: " . $sproto . "\n" };
}

print "\n\n\n";

if($getOptions) { print getOptions($host,$source,$sport); exit; }

my @requestTypes01=('BYE','OPTIONS','PRACK','PUBLISH','INFO','MESSAGE','UPDATED','REFER','SUBSCRIBE','NOTIFY');
#my @requestTypes01=('REGISTER','INVITE','BYE','OPTIONS','PRACK','PUBLISH','INFO','MESSAGE','UPDATED','REFER','SUBSCRIBE','NOTIFY');

if($detectVersion || $verbose) {
  my $response = getOptions($host,$source,$sport);
  if(lc($response) =~ m/\nserver: (.[^\n]+)\n/s) {
    print 'Server Header Detected: '.$1."\n";
    print "This is probably A PBX. Adjusting SIP methods accordingly.\n";
    @requestTypes01=('REGISTER','INVITE','BYE','OPTIONS','PRACK','PUBLISH','INFO','MESSAGE','UPDATED','REFER','SUBSCRIBE','NOTIFY');
  }elsif(lc($response) =~ m/\nuser-agent: (.[^\n]+)\n/s) {
    print 'Phone Version Detected: '.$1."\n";
    @requestTypes01=('INVITE','BYE','OPTIONS','PRACK','PUBLISH','INFO','MESSAGE','UPDATED','REFER','SUBSCRIBE','NOTIFY');
    print "This is probably an end user device. Adjusting SIP methods accordingly.\n";
  }else{
    print "No Server nor User-Agent header.\n";
  }
}

my @packTypes = ('c');
my @strOverflows = ("A",pack("H*",(0x61.0x00)),pack("H*",(0x0d.0x0a)),pack("H*",(0x1b)),pack("H*",(0x00)));

my $strOverflowLen = $#strOverflows;
for(my $i=0;$i<=$strOverflowLen;$i++) {
  push(@strOverflows,$strOverflows[$i]x32768);
  push(@strOverflows,$strOverflows[$i]x16384);
  push(@strOverflows,$strOverflows[$i]x8192);
  push(@strOverflows,$strOverflows[$i]x4096);
  push(@strOverflows,$strOverflows[$i]x2048);
  push(@strOverflows,$strOverflows[$i]x1024);
  push(@strOverflows,$strOverflows[$i]x512);
  push(@strOverflows,$strOverflows[$i]x256);
  push(@strOverflows,$strOverflows[$i]x128);
}

my @strFormats = ('%c','%d','%i','%e','%E','%f','%g','%G','%o','%u','%x','%X','%p','%s','%n');
my $strFrmtLen = $#strFormats;
for(my $i=0;$i<=$strFrmtLen;$i++) {
    push(@strOverflows,$strFormats[$i]x32768);
    push(@strOverflows,$strFormats[$i]x16384);
    push(@strOverflows,$strFormats[$i]x8192);
    push(@strOverflows,$strFormats[$i]x4096);
    push(@strOverflows,$strFormats[$i]x2048);
    push(@strOverflows,$strFormats[$i]x1024);
    push(@strOverflows,$strFormats[$i]x512);
    push(@strOverflows,$strFormats[$i]x256);
    push(@strOverflows,$strFormats[$i]x128);
    push(@strOverflows,substr($strFormats[$i],0,1)."9999999".substr($strFormats[$i],1,1));
    push(@strOverflows,substr($strFormats[$i],0,1).".4097".substr($strFormats[$i],1,1));
    push(@strOverflows,substr($strFormats[$i],0,1).".9999".substr($strFormats[$i],1,1));
    push(@strOverflows,substr($strFormats[$i],0,1)."-.0".substr($strFormats[$i],1,1));
}

my @chars = (" ",":","<",">","@",".","/",";","=","-","\n","\t","\r"); #CUT THIS UP W/DENSITY
for(my $i=0;$i<=$#chars;$i++) {
    push(@strOverflows,$chars[$i]x32000);
}
push(@strOverflows,"SHOULDNOTBEINLOGS "x100);

my @intFormats = (1,0.0,.0,"0.".("0"x32000)."1",("0"x32000)."1");
my $intFormatLen = $#intFormats;
for(my $i=0; $i<=$#chars;$i++) {
  push(@intFormats,$intFormats[$i]*-1);
}

my @xssInjections=(  '<script>alert(PAYLOAD)</script>',
      '"><script>alert(PAYLOAD)</script>',"'><script>alert(PAYLOAD)</script>",
      '" style="javascript:alert(PAYLOAD);"',"' style='javascript:alert(PAYLOAD);'",
      '" onload="alert(PAYLOAD);"',"' onload='alert(PAYLOAD);'",
      '<IMG SRC="javascript:alert(\'PAYLOAD\');">',"<IMG SRC='javascript:alert(\"PAYLOAD\");'>",
      '<IMG """><SCRIPT>alert("PAYLOAD")</SCRIPT>">',"<IMG '''><SCRIPT>alert('PAYLOAD')</SCRIPT>'>");

my @headerInjections=("\nSipFuzzerHeader: value\n");


#my @logInjection=("[DATE] NOTICE[4069] chan_sip.c: Registration from '2 <sip:voip0day@$source>' failed for '$source' - No matching peer found");

#path needs to be updated: 
#my @pbxWare=("");
#my @trixBox=("");
#my @fonality=("");
#my @switchVox=("");
#my @cisco=("");
#my @avaya=("");
#my @aastra=("");
#my @asteriskRealtime=("");
#my @startFishPBX=("");


my @sqlInjections=("' or 1=1",'" or 1=1',"' or 1=0",'" or 1=0');

if($density >= 10) {
  push(@requestTypes01,'ACK','CANCEL');
}


my @headerTypes=('Via','Max-Forwards','Contact','To','From','User-Agent','Call-ID','To','From','User-Agent','Call-ID','CSeq','Content-Type','Content-Length'); #Route, Record-Route,

my %responseCodes = (100=>'Trying',
      180=>'Ringing',
      181=>'Call Is Being Forwarded',
      182=>'Queued',
      183=>'Session Progress',
      200=>'Ok',
      202=>'Accepted: Cannot Process',
      300=>'Multiple Choices',
      301=>'Moved Permanetly',
      302=>'Moved Temporarily',
      305=>'Use Proxy',
      380=>'Alternative Service',
      400=>'Bad Request',
      401=>'Unauthorized',
      402=>'Payment Required',
      403=>'Forbidden',
      404=>'Not Found',
      405=>'Method Not Allowed',
      406=>'Not Acceptable',
      407=>'Proxy Authentication Required',
      408=>'Request Timeout',
      409=>'Conflict',
      410=>'Gone',
      412=>'Consitional Request Failed',
      413=>'Request Entity Too Large',
      414=>'Request-URI Too Long',
      415=>'Unsupported Media Type',
      416=>'Unsupported URI Scheme',
      417=>'Unknown Resource-Priority',
      420=>'Bad Extension',
      421=>'Extension Required',
      422=>'Session Interval Too Small',
      423=>'Inverval Too Brief',
      424=>'Bad Location Information',
      428=>'Use Identity Header',
      429=>'Provide Referrer Identity',
      433=>'Anominity DIssalowed',
      436=>'Bad Identity-Info',
      437=>'Unsupported Certificate',
      438=>'Invalid Identity Header',
      480=>'Temporarily Unavailable',
      481=>'Call/Transaction Does Not Exist',
      482=>'Loop Detected',
      483=>'Too Many Hops',
      484=>'Address Incomplete',
      485=>'Ambiguous',
      486=>'Busy Here',
      487=>'Request Terminated',
      488=>'Not Acceptable Here',
      489=>'Bad Event',
      491=>'Request Pending',
      493=>'Undecipherable S/MIME Body',
      494=>'Security Agreement Required',
      500=>'Internal Server Error',
      501=>'Not Implimented: REQUEST METHOD',
      502=>'Bad Gateway',
      503=>'Service Unavailable',
      504=>'Server Time-Out',
      505=>'Version Not Supported: SIP PROTOCOL',
      513=>'Message Too Large',
      580=>'Precondition Failure',
      600=>'Busy Everywhere',
      603=>'Decline',
      604=>'Does Not Exist Anywhere',
      606=>'Not Acceptable'
      );

sub sendFiniteMutation {
    my($pack,$index,$injectString,@args)=@_;

    deliverPacket(substr($pack,0,$index).$injectString,$proto);
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index),$proto);
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index-1),$proto);
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index+1),$proto);
    deliverPacket(substr($pack,0,$index-1).$injectString,$proto);
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index),$proto);
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index-1),$proto);
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index+1),$proto);
    deliverPacket(substr($pack,0,$index+1).$injectString,$proto);
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index),$proto);
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index-1),$proto);
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index+1),$proto);

}

my %sdpDirectives = (
      'a'=>'Session Attribute',
      'b'=>'Bandwidth Information',
      'c'=>'Connection Information',
      'e'=>'Email Address',
      'i'=>'Session Information/Media Title',
      'k'=>'Encryption Key',
      'o'=>'Owner/Creator and Session Identifier',
      'p'=>'Phone Number',
      's'=>'Session Name',
      'u'=>'URI of Description',
      'v'=>'Protocol Version',
      'z'=>'Time Zone Adjustments',
      't'=>'Time The Session Has Been Active',
      'r'=>'Repeat Times');

my $currentCallId = "0000000000";#0000000000;
if($startPosition) {
  $currentCallId = ((split('_',$startPosition))[1]);
}

my @spoofHosts = ($source,$host,'127.0.0.1');
my @sourceNames = ('bob','doesNotExistSource');
my @destNames = ('alice','doesNotExistDest');


foreach my $spoofHost(@spoofHosts) {

my $content = '';

my $lastPacketCount = 0;
 foreach my $requestType (@requestTypes01) {

#if($requestType == "REGISTER") {
#  $content = '';
#}else{
  $content = 'v=0
o=- 6 2 IN IP4 '.$spoofHost.'
s=A B C
c=IN IP4 '.$spoofHost.'
t=0 0
m=audio 15508 RTP/AVP 107 119 100 106 0 105 98 8 3 101
a=alt:1 3 : Sf+epwJ/ N2AgCbzU '.$spoofHost.' 15508
a=alt:2 2 : 16gbQBzu 3rvjxmQo '.$spoofHost.' 15508
a=alt:3 1 : CAKEYBiS GGAivEwQ '.$spoofHost.' 15508
a=fmtp:101 0-15
a=rtpmap:107 BV32/16000
a=rtpmap:119 BV32-FEC/16000
a=rtpmap:100 SPEEX/16000
a=rtpmap:106 SPEEX-FEC/16000
a=rtpmap:105 SPEEX-FEC/8000
a=rtpmap:98 iLBC/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv';

#}


my $pack = $requestType.' sip:bob@'.$host.' SIP/2.0
Via: SIP/2.0/'.$proto.' '.$source.':'.$sport.';branch=z9hG4bK-d8754z-b538815be3603112-1---d8754z-;rport='.$sport.'
Max-Forwards: 70
To: bob <sip:bob@'.$host.'>
From: "alice" <sip:alice@'.$source.'>;tag=102
Contact: <sip:bob@'.$source.'>
User-Agent: A_B_C
Call-ID: '.$currentCallId.'
CSeq: 1 '.$requestType.'
Content-Type: application/sdp
Content-Length: '.length($content).'

'.$content;


    foreach my $char (@chars) {
  my $offset = 0;
  my $index = 0;
  my $lastTimestamp = time;
  while($index != -1) {
      my $currentPosition = ($requestType.'_'.$currentCallId.'_'.$char.'_'.$index.'_'.$offset);
      if(!$startPosition || $startPosition eq $currentPosition) {
    $startPosition = undef;
    if($verbose || $countTests) { 
      print '['.currentTime().'] '.time.': ';
      print $currentPosition.": ";
      print time-$lastTimestamp." Seconds, ".($packetCount-$lastPacketCount)." Packet Count, ";
      if(time == $lastTimestamp) { $lastTimestamp--; }
      print (($packetCount-$lastPacketCount)/(time-$lastTimestamp));
      print " Connections Per Second\n";

      $lastTimestamp = time;
      $lastPacketCount = $packetCount;
    }

    my $fuzz='';
    if($density >= 1) {
      deliverPacket(substr($pack,0,$index));#first to index
      deliverPacket(substr($pack,0,$index-1));
      deliverPacket(substr($pack,0,$index+1));
    }    

    my $maxCharset = 127;
    if($density >= 4) { $maxCharset = 255; };
    for(my $injectChars=0;$injectChars<=$maxCharset;$injectChars++) {
        foreach my $packType (@packTypes) {
      if($density >= 1) {
          sendFiniteMutation($pack,$index,pack($packType,$injectChars));
      }
        }
    }
    if($density >= 1 || $stringFormats) {
      foreach my $strFormat (@strFormats) {
          sendFiniteMutation($pack,$index,$strFormat);
      }
    }
    if($density >= 1 || $stringOverflows) {
      foreach my $strOverflow (@strOverflows) {
          sendFiniteMutation($pack,$index,$strOverflow);
      }
    }
    if($density >= 1 || $integerFormats) {
      foreach my $intFormat (@intFormats) {
          sendFiniteMutation($pack,$index,$intFormat);
      }
    }
    if($density >= 2 || $xss) {
      foreach my $xssInject (@xssInjections) {
          $currentPosition = HTML::Entities::encode($currentPosition);
          $currentPosition = HTML::Entities::encode($currentPosition,' ');
          
          $xssInject=~s/PAYLOAD/\'$currentPosition\'/;
          sendFiniteMutation($pack,$index,$xssInject);
      }
    }
    if($density >= 2 || $injectHeaders) {
      foreach my $header (@headerInjections) {
        sendFiniteMutation($pack,$index,$header);
          #send variable that enables a regex via the response.
      }
    }
    if($density >= 2 || $sqli) {
      foreach my $sqlInject (@sqlInjections) {
          sendFiniteMutation($pack,$index,$sqlInject);
      }
    }
          deliverPacket(substr($pack,0,$index-1).substr($pack,$index+1));
      }else{
    if($verbose) { print $requestType.'_'.$char.'_'.$index.'_'.$offset."\n"; }
      }

      $offset = $index+1;
      $index = index($pack,$char,$offset);
  }
    }
 }
}
if($verbose) { print "Packet Count: ".$packetCount."\n"; }
exit;

sub sendFiniteMutation {
    my($pack,$index,$injectString,@args)=@_;

    deliverPacket(substr($pack,0,$index).$injectString);
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index));
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index-1));
    deliverPacket(substr($pack,0,$index).$injectString.substr($pack,$index+1));
    deliverPacket(substr($pack,0,$index-1).$injectString);
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index));
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index-1));
    deliverPacket(substr($pack,0,$index-1).$injectString.substr($pack,$index+1));
    deliverPacket(substr($pack,0,$index+1).$injectString);
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index));
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index-1));
    deliverPacket(substr($pack,0,$index+1).$injectString.substr($pack,$index+1));
  
}

sub checkCollision {
  my($data,@args)=@_;
  if($md5) {
    my $hash = md5_hex($data);
    if(grep(/$hash/,@md5Requests)) {
      return 0;
    }
    push(@md5Requests,$hash);
    return 1;
  }elsif($md4) {
    my $hash = md4_hex($data);
    if(grep(/$hash/,@md4Requests)) {
      return 0;
    }
    push(@md4Requests,$hash);
    return 1;
  }elsif($crc32) {
    my $hash = crc32($data);
    if(grep(/$hash/,@crc32Requests)) {
      return 0;
    }
    push(@crc32Requests,$hash);
    return 1;
  }elsif($crc16) {
    my $hash = crc16($data);
    if(grep(/$hash/,@crc16Requests)) {
      return 0;
    }
    push(@crc16Requests,$hash);
    return 1;
  }
  return 1
}

sub deliverPacket {
  my($data,$proto,@args)=@_;
  if(checkCollision($data)) {
    $packetCount++;
    if($countTests) {
      return 0;
    }
    return sendSocket($data,$host,$dport,$proto);
  }else{
    if($verbose) { print "\nSkipping Collition Packet\n"; }
    #if($verbose) { print "MD5 COLLISION!!!!!!!!!\n"; }
    #if($verbose) { print "."; }
  }
  if($callId) { $currentCallId++; };
}

sub timeoutDetection {
  my($packetNumber,@args)=@_;
}

sub sendSocket {
        my($msg,$ipaddr,$dport,$proto,@args)=@_;
  my $response='';
  my $sock = new IO::Socket::INET->new(
          #LocalPort=>$sport,
          Proto=>$proto,
          PeerPort=>$dport,
          PeerAddr=>$ipaddr) or die "CANT OPEN SOCKET!!!\n$@\n";
#      $sock->send($msg);
      print $sock $msg;

    if($connection) {
  my $MAXLEN = 1024;
  my $TIMEOUT = .1;
  if(defined($timeout) & $timeout ne '' && $timeout != 0) { #timeout of 0 hangs
    $TIMEOUT=$timeout;
  }
  eval {
    local $SIG{ALRM} = sub { die "alarm time out"; };
    alarm $TIMEOUT;
    $sock->recv($response,65535) or next;

      my $retVal = parseResponse($response,$msg);
      if($retVal == 200) {
        if(defined($veryVerbose)) {
          print "\n\n\n\n\n".$msg."\n\n\n";
        }
#send ack then bye when recieved 200, make sure there is no SDP info -> content-length=0
#once sent bye wait for 200 response.
        print "\t\tSENDING RECURSIVE REQUEST\t200\n";
        sendSocket($msg,$ipaddr,$dport,$timeout,$proto);
        print "\t\tCLEANING RECURSIVE REQUEST\n";
      }elsif($retVal == 100) { #wait on 100 for another packet., should be a 200
  #      print "\t\tSENDINT RECURSIVE REQUEST\t100\n";
  #      sendSocket($msg,$ipaddr,$dport,$timeout);
  #      print "\t\tCLEANING RECURSIVE REQUEST\n";
      }elsif($retVal == 401) {
  #      print "\t\tSENDINT RECURSIVE REQUEST\t401\n";
  #      sendSocket($msg,$ipaddr,$dport,$timeout);
  #      print "\t\tCLEANING RECURSIVE REQUEST\n";
      }
      return $response;
      #return($respaddr,$dport);
  }; 
  $sock->close();
    }
}

sub parseResponse {
  my($msg,$request,@args)=@_;
  my @lines=split("\n",$msg);
  my @words = split(" ",$lines[0]);

#######RULE 1: Abnormal Response Code
#  if($words[1] != 404 && $words[1] != 501 && $words[1] != 503 && $words[1] != 488) {
#    if(!$verbose) { print $words[1]."\t".$responseCodes{$words[1]}."\n"; }
#  }
#######END RULE 1
print "\t\t".$words[1]."\t".$responseCodes{$words[1]}." ......... ";
print substr($words[1],0,3);

  if(defined($veryVerbose)) {
    print $msg."\n\n\n";
  }
  if($density >= 2 || $injectHeaders) {
    if($msg =~ /SipFuzzerHeader: value/) {
      print "\t\t\tHEADER INJECTION\n";
      print "\t\t\tHEADER INJECTION\n";
      print "\t\t\tHEADER INJECTION\n";
      print "\t\t\tHEADER INJECTION\n";
      print $request."\n\n".$msg."\n\n";
    }
  }
  if(substr($words[1],0,1)==1) {#PROVISIONAL
    if(substr($words[1],1,2)== 00) {
      return 100;
    }
  }elsif(substr($words[1],0,1)==2) {#SUCCESS
    if(substr($words[1],1,2)== 00) {
      #if(defined($veryVerbose)) {
        print "\t\t200\n\n";
      #}
      return 200;  
    }else{
      #if(defined($veryVerbose)) {
        print "\t\t2XX\n\n";
      #}
      return substr($words[1],0,3);
    }
  }elsif(substr($words[1],0,1)==3) {#REDIRECTION
  }elsif(substr($words[1],0,1)==4) {#CLIENT ERROR
    if(substr($words[1],1,2) == 01) {
      foreach my $line(@lines) {
        if($line =~ /^WWW-Authenticate/) {
          return 401;
        }
      }
    }elsif(substr($words[1],1,2) == 04) {
      return 404;
    }
  }elsif(substr($words[1],0,1)==5) {#SERVER ERROR
  }elsif(substr($words[1],0,1)==6) {#GLOBAL FAILURE
  }
}

sub displayHelp {
  print "THIS IS THERE TO PUT THE HELP REFERENCE\n";
  exit;
}

#http://perl.about.com/od/perltutorials/a/perllocaltime_2.htm
sub currentTime {
  my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
  my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
  my($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings) = localtime();
  my $year = 1900 + $yearOffset;
  my $theTime = "$hour:$minute:$second, $weekDays[$dayOfWeek] $months[$month] $dayOfMonth, $year";
  return $theTime;
}

sub getOptions {
  my($dhost,$source,$sport,$proto,@args)=@_;

my $request = 'OPTIONS sip:bob@'.$dhost.' SIP/2.0
Via: SIP/2.0/UDP '.$source.':'.$sport.'
From: sip:alice@'.$source.';tag=55a66b
To: sip:bob@'.$dhost.'
Call-ID: 70710@'.$source.'
CSeq: 1 OPTIONS';

  return deliverPacket($request, $proto);
}
