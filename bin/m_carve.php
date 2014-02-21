#!/usr/bin/php
<?php
# ----------------------------------------------------------------------
# m_carve.php - Perform extraction of flows spanning multiple files
#
# Copyright (C) 2013
# Evan Stuart <evan.stuart@gtri.gatech.edu>
# 
#                     
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------
//Given a start and stop file, the location of the files and their pre-fix, 
//this function puts file names that fit the start-stop parameter and stores
//the results in an array
function carve($start, $stop, $dir, $pre){

		//tokenize start and end file name by (.)
		$start_token = explode(".",$start);
		$stop_token  = explode(".",$stop);
		
		//check to make sure file is in (prefix).(suffix) format (size 2)
		if(count($start_token)!=3 or count($stop_token)!=3){
			print "Invalid file name format, must be two strings separated by a period (eg. cxt.12345)\n";
		}
		else{
			//assign start and end timestamp
			$start_tstamp = $start_token[2];
			$stop_tstamp  = $stop_token[2];
			//store capture directory contents into variable
			$dircontents = list_dir($dir,$pre);
			//extract since it was passed from list_dir function
			extract($dircontents);
			//if first x digits match (in this case 6) then treat them as matches
			//and add to the results array
			$carve_results = array();
			$j=$i=0;
			for($i; $i<(count($dircontents)); $i++){

				if(substr_compare($start_tstamp,$dircontents[$i],0,5)==0){
					if($dircontents[$i]>=$start_tstamp and $dircontents[$i]<=$stop_tstamp){
						$carve_results[$j]=$dircontents[$i];
						$j++;
					}	
				}
			}
		}
	
	//sort results and return array
	sort($carve_results);
	return $carve_results;
}

//takes directory and file prefix and adds all files in the directory
//with the given prefix to an array ($valid_files)
function list_dir($directory,$pre){

	$directory = $directory;
	$open_directory = opendir($directory);
	$valid_files=array();
	while($filename = readdir($open_directory)){
		$filesplit = explode(".", $filename);
		
		$check_prefix = $filesplit[0] .".". $filesplit[1];
		if($check_prefix==$pre or $check_prefix == "openfpc-Default_Node.pcap"){						
			$valid_files[] = $filesplit[2];
		}
	}
	closedir();
	return $valid_files;
}



//Takes sorted list of files, the directory they are located in and the prefix of the 
//file name as arguments and retrieves each file's size and stores it in an array
function get_sizes($files_array,$dir,$pre){

	//var_dump($files_array);
	for($i=0;$i<count($files_array);$i++){
		$postfix = $files_array[$i];
		$size =filesize("$dir"."$pre"."."."$postfix");
		//print "Size: ".$size;
		$size_array[$i] = $size;
	}

	return $size_array;

}

//Takes carved out files and their sizes as arguments along with user supplied arguments
//to make calls to cxt2pcap.pl and produces an out file for each
//call and stores it in a folder located in the /tmp/ directory
function cxt2pcap($files2search,$file_sizes,$options,$direc){

	extract($options);
	extract($files2search);
	$dirname = '/tmp/multicarve_results/';

	//if tmp directory doesnt exist create it
	if (!file_exists($dirname)) {
	    mkdir($dirname, 0755);
	} 

	$j=1;
	$outFiles = array();
  	for($i=0;$i<count($files2search);$i++){
			
			//for each each outfile give it an unique identity to prevent collisions
  			//and store them in outfiles array so you can pass the names to mergeFiles
  			$outFiles[$i] = $dirname.md5(uniqid(mt_rand(), true)).'_out'.$j.'.pcap';

  			//build the cxt2pcap search string, first file uses supplied -s argument other default
  			//to 24, last file uses supplied -e argument the rest default to filesize
			$search_string ='-r '.$direc.$pre.'.'.$files2search[$i].
							' -w '.$outFiles[$i].
							' --src-ip '.$options["srcip"].
							' --dst-ip '.$options["destip"].
							' --src-port '.$options["srcport"].
						    ' --dst-port '.$options["destport"].
						    ' --proto '.$options["proto"].
						    ' --ipversion '.$options["ip-version"];
						    //if its the first file set -s to provided start offset
						    if($i==0){
						    	$search_string.= " -s ".$options["s"];
						    }
						    //all other files use -s 24
						    else{
								$search_string.= " -s 24";
							}
							//for the last file use -e option rather than file size
							if($i==count($files2search)-1){
								$search_string.= " -e ".$options["e"];
							}
							else{
								$search_string.= " -e ".$file_sizes[$i];
							}
			$command = 'perl /home/xubuntu/Desktop/cxtracker/bin/cxt2pcap.pl '.$search_string;
			exec($command,$out);				
			$j++;
	}
	return $outFiles;
}

function mergeFiles($outFiles){
	
	extract($outFiles);
	//declare an empty string to use in for loop
	$fileString = "";
	for($i=0; $i < count($outFiles);$i++){
		$file = $outFiles[$i];
		if(!file_exists($file)){
			print "ERRORz!!\n";
		}
		else{
		$fileString.=" ".$outFiles[$i];
		}
	}

	//need to make result have uniqid to prevent access collisions
	//executes mergecap command and saves output in tmp/multicarve_results
	$id = md5(uniqid(mt_rand(), true));
	exec('mergecap -w /tmp/multicarve_results/'.$id.'_output.pcap'.$fileString);

	//now that we have our results we delete the out.pcap files
	for($i=0; $i < count($outFiles);$i++){
		$file = $outFiles[$i];
		unlink($file);
	}

	$handle = fopen('/tmp/multicarve_results/'.$id.'_output.pcap', "r");
	return $handle;
}

//define command line arguments
$shortopts  = "";			
$shortopts .= "s:"; 		//Byteoffset on where to start carving
$shortopts .= "e:";
$shortopts .= "a:";
$longopts  = array(
    "sfile:",     		//file to start search at, required
    "efile:",    		//file to end search at, required
    "dir:",				//path to directory of pcap files
    "pre:",				//prefix of files you are searching
    "srcip:",			//source IP
    "destip:",			//destination ip
    "srcport:",			//source port
    "destport:",		//destination port
    "proto:",        	//protocol
    "ip-version:",		//ip-version either 4 or 6
);

$options = getopt($shortopts, $longopts);

//map options to variables

if($options["a"]=="yes"){
	$unixTime= explode(".",$options["sfile"]);
	$date = date("Y-m-d", $unixTime[1]);
	$dir=$options["dir"].$date."/";
	$direc =$options["dir"].$date."/";
  }
else{
	$dir = $options["dir"];
	$direc = $options["dir"].$date."/";
  }
// $dir = $options["dir"];
// $direc = $options["dir"]; //.$date."/";
$start = $options["sfile"];
$stop  = $options["efile"];
$pre   = $options["pre"];

//var_dump($options);

//get files to search
$files2search = carve($start,$stop,$dir,$pre);
//$files2search = carve($options);
//get sizes of the files you want to search
$file_sizes = get_sizes($files2search,$dir,$pre);
//construct and call cxt2pcap searches, return generated outfiles
$outputfiles = cxt2pcap($files2search,$file_sizes,$options,$direc);
//take generated outfiles and merge them into one pcap
$fileHandle = mergeFiles($outputfiles);
//return file handle of the merged pcap file
$meta_data = stream_get_meta_data($fileHandle);
$filename = $meta_data["uri"];
print $filename;
return $filename;
?>
