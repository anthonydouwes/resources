/*
	todo: 1) get rid of captureLen
*/
function PcapPacket(bytes) {
  this.data = [];
  this.size = 0;
  var incl_len = getIntReverse(bytes, 8);
  
  if(bytes.length > 0 && incl_len > 0 && incl_len <= bytes.length) {
	this.data = bytes;
	this.size = incl_len + 16; //+pcap header len;	
  }
  
  this.networkType = -1;
  if(this.size >= 30)
	this.networkType = getShort(this.data, 28);

  this.transportType = -1; 
  if(this.networkType==0x86dd  && this.size>=37) { //IPv6
	this.transportType = getByte(this.data, 36);
  } else if (this.networkType==0x800  && this.size>=40) {  //IPv4
	this.transportType = getByte(this.data, 39); 
  }
  
  this.payloadOffset = getPayloadOffset(this.networkType, this.transportType, this.size, this.data);

  /***************** public methods *****************/

  this.getSize = function() {
	return this.size;
  }
  
  this.getPayload = function() {
	var ret = [];
	if(this.hasData() == true)
	  ret = getBytes(this.data, this.payloadOffset, this.size);
	return ret;
  }
  
  this.hasData = function() {
	var ret = false;
	if(this.size > 0)
		ret = (this.size-this.payloadOffset) > 0;
	return ret;
  } 
  
  this.toStr = function() {
	return ("size: " + this.size.toString()
			  + " payload offset: " + this.payloadOffset.toString()
			  + " has data: " + this.hasData().toString()
			  + " payload size: " + (this.size-this.payloadOffset).toString()
			  + " network type: " + (this.networkType==0x86dd?"IPv6":"IPv4")
			  + " transport type: " + (this.transportType==6?"TCP":"UDP")
			  + " srcPort: " + this.getSrcPort().toString()
			  + " dstPort: " + this.getDstPort().toString()
			 );
  }
  
  this.getNetworkType = function() {
	return this.networkType;
  }
  
  this.getTransportType = function() {
	return this.transportType;
  }

  this.getSrcPort = function() {
	var trpHdrOffset = 
		16 + 14 + 
		(this.networkType==0x8100?2:0) +	//VLAN Q-tags
		(this.networkType==0x86dd?40:20)	//network header
	;
	
	return getShort(this.data, trpHdrOffset);
  }

  this.getDstPort = function() {
	var trpHdrOffset = 
		16 + 14 + 
		(this.networkType==0x8100?2:0) +	//VLAN Q-tags
		(this.networkType==0x86dd?40:20)	//network header
	;
	
	return getShort(this.data, trpHdrOffset+2);
  }


  /***************** private functions *****************/

  function getPayloadOffset(nwType, trType, size, buf) {	
	var nwHdrLen = 20;  //default IPv4 hdr, length 20 bytes
	var vlanFlagsLen = 0;
	var trlHdrLen = 8; 	//UDP header is 8 bytes

	if(nwType < 0 || size <= 0) {
	  return 0;
	} else if(nwType == 0x86dd) { //IPv6
	  nwHdrLen = 40;			//IPV6 network layer header is 40 bytes
	}

	if (nwType == 0x8100) {//VLAN (https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
	  vlanFlagsLen = 2;
	}

	if(size >= 65 && trType == 6) {	//TCP
	  trlHdrLen = (((buf[62]>>4)&0xf) * 4);
	}
	
	return ( 
	  16  			 //tcpdump header: ts_sec, ts_usec, incl_len, orig_len
	  + 14 			 //link-layer header: srcMac 6, dstMac 6, nwHdrType 2 bytes
	  + vlanFlagsLen //vlan labels
	  + nwHdrLen 	 //network layer header	
	  + trlHdrLen    //transport layer header
	);	
  }

}

/******************* public helper functions *****************/

function getByte(buf, pos) {
  return buf.length > pos ? buf[pos]&0xff : 0;
}

function getBytes(buf, from, to) {
  var ret = [];
  if(from > buf.length || to > buf.length || from < 0 || to < 0) return ret;
  for(var i=0; i+from<to; i++) {
	ret.push(buf[from+i]&0xff);
  }  
  return ret;
}

function bytesToStr(byteArray, from, to) {
  var ret = [];
  if(from > byteArray.length || to > byteArray.length || from < 0 || to < 0) return ret;
  for(var i=0; from+i<to; i++) {
	if(i%16==0) ret.push("\n");
	ret.push(pad((byteArray[from+i]&0xff).toString(16),2) + " ");
  }
  return ret.join("");
}

function getShort(buf, pos) {
  return buf.length > pos+1 ? (((buf[pos]<<8)&0xff00) | (buf[pos+1]&0x00ff)) : 0;
}

function getInt(buf, pos) {
  if(buf.length <= pos+3) return 0;
  return ( ((buf[pos]<<24)&0xff000000) 
			 | ((buf[pos+1]<<16)&0xff0000) 
			 | ((buf[pos+2]<<8)&0xff00) 
			 | (buf[pos+3]&0xff) 
			);  
}

function getShortReverse(buf, pos) {
  return buf.length > pos+1 ? (((buf[pos+1]<<8)&0xff00) | (buf[pos]&0x00ff)) : 0;
}

function getIntReverse(buf, pos) {
  if(buf.length <= pos+3) return 0;
  return ( ((buf[pos+3]<<24)&0xff000000) 
			 | ((buf[pos+2]<<16)&0xff0000) 
			 | ((buf[pos+1]<<8)&0xff00) 
			 | (buf[pos]&0xff) 
			);    
}

function pad(num, size) {
  var s = ""+num;
  while (s.length < size) s = "0" + s;
  return s;
}



