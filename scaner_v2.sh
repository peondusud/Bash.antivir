#!/bin/bash
#
#bash antivir project
#using clamAV signature DATABASE
#ClamAV metacharacters ?*{}()|![]-
#in the HexSignature are silently ignored
#
#Author: peondusud
#26/11/2012
#
function usage()
{
echo "Usage" `basename $0`
echo ""
echo "NAME"
echo "     " `basename $0` " - bash antivirus scanner"
echo ""
echo "SYNOPSIS"
echo ""
echo "    " `basename $0` "[-s DATABASE]  [-f FILE] [-r FOLDER] [-v OPTION] "
echo ""
echo "DESCRIPTION"
echo ""
echo "    " `basename $0` " scan files or directories given in the script options, to check if files contain one of the signatures given in a signature database. using Bash and standard Unix commands such as grep, od, awk, sed, find.."
echo ""
echo "OPTIONS"
echo ""
echo "    -f file = one file mode" 
echo "    -r folder = recursive mode" 
echo "    -s DATABASE = select DATABASE" 
echo "    -v = VERBOSE mode" 
echo ""
exit 1
}

function echo_verbose()
{
if [ "$verbose" == "1" ]; then
echo  -e "$1"
fi
}

function entrance()
{
verbose=0
if [ "$#" == "0" ]; then
usage
fi
while getopts ":hvr:s:f:" opt; do
  case $opt in
    h)
      usage  ;;
    v)
      echo "-v was triggered, Verbose mode"
      verbose=1 ;;
    f)
      folder_path=$OPTARG ;;
    r)
      folder_path=$OPTARG ;;
    s)
      signature_path=$OPTARG ;;
    \?)
      echo "Invalid option: -$OPTARG"
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument."
      exit 1
      ;;
  esac
done
}

function recursive_files()
{
files=$(find $folder_path -type f)
for f in $files
do
    #make od dump and scan the file
    raw_and_scan "$f" &
    #stuff to limit thread must be adapt to each CPU
    while (( $(jobs | wc -l) >= 6 )); do
        sleep 0.1
        jobs > /dev/null
    done
done
wait
}

#parameter file path
function raw_and_scan()
{
raw_test_file $1
target_type $1
read_signature_db_by_line $1
}


function  raw_test_file()
{
#od dump
raw_file=$(od -t x1 -An $1 |tr -d '\n ')
#raw_file=$(xxd -p file | tr -d '\n')
}

 #read line by line each in a thread and try to match each pattern
function  read_signature_db_by_line()
{
cat $signature_path | (while read LINE ; do
       #read line by line each in a thread
	stringtokenizer_line_db	$LINE $1 $raw_file &
	    #stuff to limit thread must be adapt to each CPU
	    while (( $(jobs | wc -l) >= 8 )); do
		sleep 0.1
		jobs > /dev/null
	    done
done
wait
)
}

#check target type of each file
#TRICK: if it don't find a patern put equals to 0
function target_type()
{
type_file=0
opt=$(file  $1 | awk '{print $2}')
 case $opt in
    "Mach-O" )
      type_file=8 ;; #Mach-O ﬁles
    "ASCII" )
      type_file=7 ;;
    "ELF" )
      type_file=6 ;;
    "PNG" | "JPEG" | "BMP" | "GIF" | "TIFF" )
      type_file=5 ;; #graphics
    "MAIL" )
      type_file=4 ;; #mail
    "HTML" )
      type_file=3 ;;
    "RICH" | "Composite" )
      type_file=2 ;;  #RTF #OLE2
    "PE32" | "PE64")
      type_file=1 ;; #Portable Executable
    * )
      type_file=0 ;; # Otherwise
  esac
}

function stringtokenizer_line_db()
{
line=$1
test_file_path=$2
raw_file_path=$3
name=$(echo "$line" |awk -F':' '{ print $1 }')
target_type=$(echo "$line" |awk -F':' '{ print $2 }')
offset=$(echo "$line" |awk -F':' '{ print $3 }')
signature=$(echo "$line" |awk -F':' '{ print $4 }')

#echo_verbose "\e[1;33m' $name ** $target_type ** $offset ** $signature '\e[0m"

if (( "$type_file" == "0" || "$type_file" == "$target_type" )) ; then
	
	#test to convert hexadecimal string to hex and try matching with grep NOT working
	#tmp=$(echo -n $signature | sed 's/\([0-9A-F]\{2\}\)/\\\\\\x\1/gI' | xargs print)
	#printf -v variable $(sed 's/\(..\)/\\x\1/g;' <<< "$signature")
	#test_var=$(grep -UE "$variable" "$raw_file_path")
	
		if [ "$offset" == "*" ] ; then
		test_var=$(echo $raw_file_path | grep $signature )
		else
		# add signature length to offset
	 	size=$( echo "$offset ${#signature}" | awk '{print $1+$2}')
		#chunk of signature size start at $offset
		test_var=$(echo $raw_file_path | dd skip=$offset count=$size bs=1 2> /dev/null | grep  $signature ) 
		fi
	
	if [ "$test_var" ] ; then
	echo -e '\e[1;31m' $name "Virus found at " $test_file_path '\e[0m'
	echo $name "Virus found at " $(pwd)/$test_file_path >> /home/$USER/scan_report
	else
	echo_verbose "\e[1;32m $name Virus not found at  $test_file_path \e[0m"
	fi
fi
}

start_time=$(date +%s.%N)
echo "**** Start time : " $(date -d now) " ****">> /home/$USER/scan_report
echo "Scan result for " $folder_path " at " $(pwd) >> /home/$USER/scan_report
entrance "$@"
recursive_files
finish_time=$(date +%s.%N)
echo "Time duration:" $( echo "$finish_time $start_time" | awk '{print $1-$2}') "secs.nano"
echo "Scan Finished" 
echo "**** Time duration:" $( echo "$finish_time $start_time" | awk '{print $1-$2}') "secs.nano ****" >> /home/$USER/scan_report
echo "">> /home/$USER/scan_report
exit 1

#one file
#real	0m28.270s
#user	0m2.668s
#sys	0m2.200s

#test-files/ folder 10items-1.1kB
#real	4m31.305s
#user	0m29.282s
#sys	0m25.118s

#25 items 15.4kB
#real	10m56.749s
#user	1m19.941s
#sys	1m3.008s

#file   time    time/file
#1	28	28
#10	271	27.1
#25	656	26.24

#clamscan -d databases/filtered.ndb  -r test-files/
#test-files/VBS.Autorun: VBS.Autorun.UNOFFICIAL FOUND
#test-files/Trojan.Bancos-166: OK
#test-files/Trojan.DNSChanger-156: OK
#test-files/VBS.Polsev.A: VBS.Polsev.A.UNOFFICIAL FOUND
#test-files/Trojan.DNSChanger-797: OK
#test-files/Worm.Allaple-1: OK
#test-files/Trojan.Mybot-1249: OK
#test-files/Trojan.DNSChanger-155: OK
#test-files/JAVA.SendSMS: JAVA.SendSMS.UNOFFICIAL FOUND
#test-files/Worm.Stration.GC: OK

#----------- SCAN SUMMARY -----------
#Known viruses: 9371
#Engine version: 0.97.6
#Scanned directories: 1
#Scanned files: 10
#Infected files: 3
#Data scanned: 0.00 MB
#Data read: 0.00 MB (ratio 0.00:1)
#Time: 0.067 sec (0 m 0 s)


#one file
#real	0m28.270s
#user	0m2.668s
#sys	0m2.200s

#test-files/ folder 10items-1.1kB
#real	4m31.305s
#user	0m29.282s
#sys	0m25.118s

#25 items 15.4kB
#real	10m56.749s
#user	1m19.941s
#sys	1m3.008s

#1	28	28
#10	271	27.1
#25	656	26.24

