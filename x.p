#!/usr/bin/perl -w
use strict;
use Digest::SHA qw (sha256_hex);
use Math::BigInt only => 'GMP';
my $tm1 = time; 
# A ENCRYPTION - Version 0.1
# 64 * 8 bits ~ 64 Bytes/512 bits 
# THIS WAS WRITTEN BY ALIEN - alienzone@null.net - 17-06-2018-0222
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/3.0/.

# INITIALIZE GLOBAL PARAMETERS
my $ts; # For temporary usages - cup holder =D
my $tt; # For temporary usages - cup holder =D
my $tu; # For temporary usages - cup holder =D
my $tv; # For temporary usages - cup holder =D
my @ta; # For temporary usages - cup holder =D
my @tb; # For temporary usages - cup holder =D
my $msg; # message holder
my $nn; # nonce number - changes as block-count goes up
my $NN; # big nonce for calcs
my $sn; # small nonce for other calcs
my $SN; # big small nonce for other calcs
my $key; # key/password - must be 64bytes
my $khs; # key/password hash - 64bytes - the actual key used to cipher - gets rotated and fuzzed
my @KEY; # big key/password
my $slt; # salt number - transmitted with cipher
my $SLT; # big salt
my @SLU; # big salt container
my $out=''; # what comes out at the end =D
my %bkmp; # a 8x8 hash table - used for ciphering cells
my $zz; # counter 0
my $yy; # counter 1
my $xx; # counter 2
my $bn; # block number (64 bytes per block)
my @mbk; # message block as 64 byte slice
my $RC; # cell rotation counter

# PRELOAD GLOBALS WITH DATA
# nonce number, 64bytes 
@ta=('1'..'6');$nn='';
foreach(1..64){$nn.=$ta[rand @ta];}
# big nonce
$NN=Math::BigInt->new($nn);
# small nonce
@ta=split('',$nn);
$zz=0;$sn=0;while($zz<=63){
   $sn = $sn + ($ta[$zz] * 2);
   $zz = $zz + 1; }
# big small nonce
$SN=Math::BigInt->new($sn);

# salt number, 64bytes 
$slt='';
foreach(1..64){$slt.=$ta[rand @ta];}
# big salt
$SLT=Math::BigInt->new($slt);

# a messages to encrypt - unremark to use
$msg='Yet another test message testing the usefulness of cipher block chaining when encrypting text via a matrix style sliding table. some random letters to pad out the message : im9r8mv98m v4985 vma8v aw9845m av89 v856vekj a3opqwu3509i vmaiwvm 9aie t490ti va 094wi vat9iw 4mt9erutm vaojm poatjtm viajo e ngh aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA padding is not required as table will automagically pad the blocks. =)'; # arbitrary n bytes
#$msg='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; # 1024 bytes
#$msg='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; # 512 bytes
#$msg='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; # 256 bytes
#$msg='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; # 128 bytes
#$msg='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; # 64 bytes

# key/password
$key='arandomkeyiswhatweneed---htheretotestoutthisfunctiontomakeaciphe';

# DISPLAY MESSAGE BEFORE ENCRYPT
print "msg $msg\n\n";

### ENCODE
sub encode { 
#   # GRAB INPUT
#   ($msg) = @_;
   $out='';

print "ENCODE:\n";
   # KEY HASH
   @ta=[];$khs=sha256_hex($key);
   @ta=split('',$khs);
   $zz=0;while($zz<=63){
      $ta[$zz]=ord($ta[$zz]);
      @KEY[$zz]=Math::BigInt->new($ta[$zz]);
      $KEY[$zz]=$KEY[$zz]->bmul($KEY[$zz]);
      $zz = $zz + 1;}

   # CIPHER BLOCKMAP - 0 blkup id, 1 blkleft id, 2 key char, 3 msg char, 4 hash, 5 salt
   %bkmp = ( 0=>[1,1,$SLT,$NN,$NN,$SLT],
             1=>['0','0'],2=>['0',1],  3=>['0',2],  4=>['0',3],  5=>['0',4],  6=>['0',5],  7=>['0',6],  8=>['0',7],
             9=>[1,8],   10=>[2,9],   11=>[3,10],  12=>[4,11],  13=>[5,12],  14=>[6,13],  15=>[7,14],  16=>[8,15],
            17=>[9,16],  18=>[10,17], 19=>[11,18], 20=>[12,19], 21=>[13,20], 22=>[14,21], 23=>[15,22], 24=>[16,23],
            25=>[17,24], 26=>[18,25], 27=>[19,26], 28=>[20,27], 29=>[21,28], 30=>[22,29], 31=>[23,30], 32=>[24,31],
            33=>[25,32], 34=>[26,33], 35=>[27,34], 36=>[28,35], 37=>[29,36], 38=>[30,37], 39=>[31,38], 40=>[32,39],
            41=>[33,40], 42=>[34,41], 43=>[35,42], 44=>[36,43], 45=>[37,44], 46=>[38,45], 47=>[39,46], 48=>[40,47],
            49=>[41,48], 50=>[42,49], 51=>[43,50], 52=>[44,51], 53=>[45,52], 54=>[46,53], 55=>[47,54], 56=>[48,55],
            57=>[49,56], 58=>[50,57], 59=>[51,58], 60=>[52,59], 61=>[53,60], 62=>[54,61], 63=>[55,62], 64=>[56,63]  );

print "key $key\nkhs $khs\nKEY @KEY\n";

   # ROTATE KEY
   $zz=0;while($zz<=$sn){
      $ts = pop @KEY;
      unshift @KEY, $ts;
      $zz = $zz + 1;}

print "KEY @KEY\n\n nn $nn\n NN $NN\n sn $sn\nslt $slt\nSLT $SLT\nblk ";

   # ADD SN TO KEY
   $zz=0;while($zz<=63){
      $KEY[$zz]=$KEY[$zz]->badd($SN);
      $zz = $zz + 1; }

   # PRELOAD INITIAL KEY INTO BLOCK MAP CELL
   $zz=1; $yy=0; @ta=[]; @tb=[];
   while ($zz <= 64) {
      if ($bkmp{$zz}[0] ne '') {
         $bkmp{$zz}[2]=$KEY[$yy];
#print "$bkmp{$zz}[2] ";
         $yy=$yy+1; }
      $zz=$zz+1; }
print "\n\nBlocks:\n";

   # SPLIT MESSAGE INTO 64 BYTE BLOCKS 
   $zz=0;$bn=0;$ts=length($msg);
   while($zz<=$ts && $zz!=$ts){
      $mbk[$bn].=substr($msg,$zz,64);
#print "$mbk[$bn]\n";
      $bn=$bn+1; 
      $zz=$zz+64;}
   $bn = $bn; $ts = ($zz * 8);
print "$bn Block(s) - $zz bytes - $ts bits\nSALTS: ";

   # ROTATE CELLS WHILST MSG BLOCKS EXIST
   $RC=0;while($mbk[$RC]){

      # ADD BIG SALT TO BLOCK CELLS
      $zz=1; $yy=0; while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $SLU[$yy] = Math::BigInt->new($SLT->badd($SN));
            $bkmp{$zz}[5]=$SLU[$yy];
#print "$bkmp{$zz}[5] ";
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n MESSAGE BLOCK $RC: ";

      # ADD MSG BLOCK[n] TO BLOCKMAP
      @tb = split('',$mbk[$RC],64);
      $zz=1; $yy=0; while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            if (!$tb[$yy]){$tb[$yy]='';}
            $ts=ord($tb[$yy]);
#print "$ts ";
            $bkmp{$zz}[3]=$ts;
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n";

      # RECORD HASH KEY, XCELL, YCELL, SALTS AT CELL[n]
      # compute hash
      $zz=1;$yy=0;$ts='';while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $ts = sha256_hex($bkmp{$zz}[0].             # 1st chain cell
                             $bkmp{$zz}[1].             # 2nd chain cell
                             $bkmp{$zz}[2].             # cell key
                             $bkmp{$bkmp{$zz}[0]}[4].   # 1st chain hash 
                             $bkmp{$bkmp{$zz}[1]}[4].   # 2nd chain hash
                             $bkmp{$zz}[5]).            # salt
                             $NN;                       # big nonce
#print "HSH: $ts\n";

            # convert hash to integers
            @ta = split('',"$ts",128);
            $xx=0;$tu=0;
            while($xx<=127){
               $tb[$xx]=ord($ta[$xx]);
               $tu=$tu+$tb[$xx];
               $xx=$xx+1;}
            $tv=Math::BigInt->new($tu);

            # add hash to current cell
            $bkmp{$zz}[4] = $tv;
#print "blk: $bkmp{$zz}[4]\n";

            # update NN
            $NN=$NN->bsub($tv);
#print " NN: $NN\n";
            $yy=$yy+1; }
         $zz=$zz+1; }

      # DISPLAY BLOCKS
#      $zz=1;while($zz<=64){
#         if ($bkmp{$zz}[0] ne '') {
#            print  $zz.'='.
#                    $bkmp{$zz}[0].','.      # 1st cc
#                    $bkmp{$zz}[1].','.      # 2nd cc
#                    $bkmp{$zz}[2].','.      # cell key
#                    $bkmp{$zz}[3].','.      # cell data
#                    $bkmp{$zz}[4].','.      # computed hash
#                    $bkmp{$zz}[5]."\n" ; }  # salt
#         $zz=$zz+1; }

      # DO ENCRYPTION ON CELLS
      $zz=1;$ts=0;
      while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $ts =  ( ($bkmp{$zz}[0] + $bkmp{$zz}[1] + $bkmp{$zz}[2]) + 
                     ($bkmp{$zz}[3] + ($bkmp{$zz}[5] / $bkmp{$zz}[4])) );}
#print "\n$ts";
         $out .= $ts;
         $zz=$zz+1; }
print "\nSize of blocks total ".length($out)." bytes\n";
print "Approx ".length($out)/($RC+1)." bytes per block\n";

#print "key $key\nkhs $khs\nKEY @KEY\n";

      # ROTATE KEY
      $zz=0;while($zz<=$sn){
         $ts = pop @KEY;
         unshift @KEY, $ts;
         $zz = $zz + 1;}

      # ADD SN TO KEY
      $zz=0;while($zz<=63){
         $KEY[$zz]=$KEY[$zz]->badd($sn);
         $zz = $zz + 1; }

#print "KEY @KEY\n\n nn $nn\n NN $NN\n sn $sn\nslt $slt\nSLT $SLT\nblk ";

      # UPDATE KEY IN BLOCK MAP
      $zz=1; $yy=0; @ta=[]; @tb=[];
      while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $bkmp{$zz}[2]=$KEY[$yy];
#print "$bkmp{$zz}[2] ";
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n\nBlocks:\n";

   $RC=$RC+1;}

   print "$RC block rotation(s) performed!\n";

# UNDEFINES FOR CLEANUP
   undef $ts;undef @ta;undef %bkmp;undef $zz;undef $yy;undef $bn;undef @mbk;undef $RC;undef $ts;undef $tt;undef @ta;undef @tb;

# RETURN
   return $out;}

### DECODE
sub decode {
$key='arandomkeyiswhatweneed---htheretotestoutthisfunctiontomakeaciphe';
   $out='';
   print "DECODE\n";
   # big nonce
   $NN=Math::BigInt->new($nn);

   # big salt
   $SLT=Math::BigInt->new($slt);

   # KEY HASH
   @ta=[];$khs=sha256_hex($key);
   @ta=split('',$khs);
   $zz=0;while($zz<=63){
      $ta[$zz]=ord($ta[$zz]);
      @KEY[$zz]=Math::BigInt->new($ta[$zz]);
      $KEY[$zz]=$KEY[$zz]->bmul($KEY[$zz]);
      $zz = $zz + 1;}

   # GRAB INPUT
   ($msg) = @_;

   # CIPHER BLOCKMAP - 0 blkup id, 1 blkleft id, 2 key char, 3 msg char, 4 hash, 5 salt
   %bkmp = ( 0=>[1,1,$SLT,$NN,$NN,$SLT],
             1=>['0','0'],2=>['0',1],  3=>['0',2],  4=>['0',3],  5=>['0',4],  6=>['0',5],  7=>['0',6],  8=>['0',7],
             9=>[1,8],   10=>[2,9],   11=>[3,10],  12=>[4,11],  13=>[5,12],  14=>[6,13],  15=>[7,14],  16=>[8,15],
            17=>[9,16],  18=>[10,17], 19=>[11,18], 20=>[12,19], 21=>[13,20], 22=>[14,21], 23=>[15,22], 24=>[16,23],
            25=>[17,24], 26=>[18,25], 27=>[19,26], 28=>[20,27], 29=>[21,28], 30=>[22,29], 31=>[23,30], 32=>[24,31],
            33=>[25,32], 34=>[26,33], 35=>[27,34], 36=>[28,35], 37=>[29,36], 38=>[30,37], 39=>[31,38], 40=>[32,39],
            41=>[33,40], 42=>[34,41], 43=>[35,42], 44=>[36,43], 45=>[37,44], 46=>[38,45], 47=>[39,46], 48=>[40,47],
            49=>[41,48], 50=>[42,49], 51=>[43,50], 52=>[44,51], 53=>[45,52], 54=>[46,53], 55=>[47,54], 56=>[48,55],
            57=>[49,56], 58=>[50,57], 59=>[51,58], 60=>[52,59], 61=>[53,60], 62=>[54,61], 63=>[55,62], 64=>[56,63]  );

print "key $key\nkhs $khs\nKEY @KEY\n";

   # ROTATE KEY
   $zz=0;while($zz<=$sn){
      $ts = pop @KEY;
      unshift @KEY, $ts;
      $zz = $zz + 1;}

print "KEY @KEY\n\n nn $nn\n NN $NN\n sn $sn\nslt $slt\nSLT $SLT\nblk ";

   # ADD SN TO KEY
   $zz=0;while($zz<=63){
      $KEY[$zz]=$KEY[$zz]->badd($sn);
      $zz = $zz + 1; }

   # PRELOAD INITIAL KEY INTO BLOCK MAP CELL
   $zz=1; $yy=0; @ta=[]; @tb=[];
   while ($zz <= 64) {
      if ($bkmp{$zz}[0] ne '') {
         $bkmp{$zz}[2]=$KEY[$yy];
#print "$bkmp{$zz}[2] ";
         $yy=$yy+1; }
      $zz=$zz+1; }
print "\n\nBlocks:\n";

   # SPLIT MESSAGE INTO BLOCKS
   $zz=0;$bn=0;$ts=length($msg);
   while($zz<=$ts && $zz!=$ts){
      $mbk[$bn]=substr($msg,$zz,3840);
#print "$mbk[$bn]\n";
      $bn=$bn+1; 
      $zz=$zz+3840;}
   $bn = $bn; $ts = ($zz * 8);
print "$bn Block(s) - $zz bytes - $ts bits\nSALTS: ";

   # ROTATE CELLS WHILST MSG BLOCKS EXIST
   $RC=0;while($mbk[$RC]){

      # ADD BIG SALT TO BLOCK CELLS
      $zz=1; $yy=0; while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $SLU[$yy] = Math::BigInt->new($SLT->badd($SN));
            $bkmp{$zz}[5]=$SLU[$yy];
#print "$SLT ";
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n MESSAGE BLOCK $RC: ";

      # SPLIT MESSAGE INTO CELLS
      $zz=0;$yy=0;
      while($zz<=3839){
         $ta[$yy]=substr($mbk[$RC],$zz,60);
         $yy = $yy + 1;
         $zz = $zz + 60; }

      # ADD MSG BLOCK[n] TO BLOCKMAP
      $zz=1; $yy=0; while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $bkmp{$zz}[3]=$ta[$yy];
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n";

      # RECORD HASH KEY, XCELL, YCELL, SALTS AT CELL[n]
      # compute hash
      $zz=1;$yy=0;$ts='';while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $ts = sha256_hex($bkmp{$zz}[0].             # 1st chain cell
                             $bkmp{$zz}[1].             # 2nd chain cell
                             $bkmp{$zz}[2].             # cell key
                             $bkmp{$bkmp{$zz}[0]}[4].   # 1st chain hash 
                             $bkmp{$bkmp{$zz}[1]}[4].   # 2nd chain hash
                             $bkmp{$zz}[5]).            # salt
                             $NN;                       # big nonce
#print "HSH: $ts\n";

            # convert hash to integers
            @ta = split('',"$ts",128);
            $xx=0;$tu=0;
            while($xx<=127){
               $tb[$xx]=ord($ta[$xx]);
               $tu=$tu+$tb[$xx];
               $xx=$xx+1;}
            $tv=Math::BigInt->new($tu);

            # add hash to current cell
            $bkmp{$zz}[4] = $tv;
#print "blk: $bkmp{$zz}[4]\n";

            # update NN
            $NN=$NN->bsub($tv);
#print " NN: $NN\n";
            $yy=$yy+1; }
         $zz=$zz+1; }

      # DISPLAY BLOCKS
#      $zz=1;while($zz<=64){
#         if ($bkmp{$zz}[0] ne '') {
#            print  $zz.'='.
#                    $bkmp{$zz}[0].','.      # 1st cc
#                    $bkmp{$zz}[1].','.      # 2nd cc
#                    $bkmp{$zz}[2].','.      # cell key
#                    $bkmp{$zz}[3].','.      # cell data
#                    $bkmp{$zz}[4].','.      # computed hash
#                    $bkmp{$zz}[5]."\n" ; }  # salt
#         $zz=$zz+1; }

      # DO DECRYPTION ON CELLS
      $zz=1;$ts=0;
      while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $ts = ( ($bkmp{$zz}[3] - ($bkmp{$zz}[5] / $bkmp{$zz}[4])) - ($bkmp{$zz}[0] + $bkmp{$zz}[1] + $bkmp{$zz}[2]) ) ; }
#print "\n$ts";
         $out .= chr($ts);
         $zz=$zz+1; }
print "\nSize of blocks total ".length($out)." bytes\n";
print "Approx ".length($out)/($RC+1)." bytes per block\n";

#print "key $key\nkhs $khs\nKEY @KEY\n";

      # ROTATE KEY
      $zz=0;$ts=0;while($zz<=$sn){
         $ts = pop @KEY;
         unshift @KEY, $ts;
         $zz = $zz + 1;}

      # ADD SN TO KEY
      $zz=0;while($zz<=63){
         $KEY[$zz]=$KEY[$zz]->badd($sn);
         $zz = $zz + 1; }

#print "KEY @KEY\n\n nn $nn\n NN $NN\n sn $sn\nslt $slt\nSLT $SLT\nblk ";

      # UPDATE KEY IN BLOCK MAP
      $zz=1; $yy=0; @ta=[]; @tb=[];
      while ($zz <= 64) {
         if ($bkmp{$zz}[0] ne '') {
            $bkmp{$zz}[2]=$KEY[$yy];
#print "$bkmp{$zz}[2] ";
            $yy=$yy+1; }
         $zz=$zz+1; }
#print "\n\nBlocks:\n";

   # END ROTATE CELLS
   $RC=$RC+1;}

   # RETURN
   return $out; }

# EXIT
my $ct=encode();
my $tm2 = time;
print "ENCRYPTED MESSAGE\n$ct";
print "\n";
my $cd=decode($ct);
print $cd;
print "\n";
print "time taken: ".($tm2-$tm1)." seconds\n\n";
