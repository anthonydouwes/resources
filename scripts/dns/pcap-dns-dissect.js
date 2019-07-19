/* https://tools.ietf.org/html/rfc1035 section 4.1
   PCAP protocol dissector for DNS messages
   
   Extracts all message header fields (except Z), question and answer sections.
   Authority and additional sections are ignored.
   
   Works on IPv4, IPv6, UDP and TCP. (TCP on IPv6 not tested).
*/
var base;    //dns section position
var offset;  //current position in the dns block 
var limit;   //total pcap block size

function dissectDnsMessage(bytes, len) {
  var hasData = processHdr(bytes, len);
  
  if(!hasData){
	return {txId:-1, 
			flags:-1,
			opCode:-1,
			isQuery:false,
			isAuthoritative:false,
			isTruncated:false,
			recursionDesired:false,
			recursionAvailable:false,
			rCode:-1,
			questionCnt:-1,
			answerCnt:-1, 
			authorityCnt:-1, 
			additionalCnt:-1,
			queries:[],
			answers:[]
		   };	
  }
  if(limit >= offset+12) {
	var txId = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
	var flags = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
	var questionCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
	var answerRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
	var authorityRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
	var additionalRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  }
  var opCode = (flags>>11)&0xf;

  var qArray = [];
  for(var i=0; i<questionCnt; i++) {
	var q = getQueries(bytes);
	qArray.push(q);
  }
  
  var aArray = [];
  for(var i=0; i<answerRRCnt; i++) {
	var a = getAnswers(bytes);
	aArray.push(a);
  }
  
  return {txId:txId, 
		  flags:flags,
		  opCode:opCode,
		  isQuery:(flags&0x8000)==0,
		  isAuthoritative:(flags&0x400)!=0,
		  isTruncated:(flags&0x200)!=0,
		  recursionDesired:(flags&0x100)!=0,
		  recursionAvailable:(flags&0x80)!=0,
		  rCode:(flags&0xf),
		  questionCnt:questionCnt, 
		  answerCnt:answerRRCnt, 
		  authorityCnt:authorityRRCnt, 
		  additionalCnt:additionalRRCnt,
		  queries:qArray,
		  answers:aArray
		 };
}

function getAnswers(buf) {
  var ret = new Object();
  ret.address = "";
  
  if((offset + 8) > limit) return ret;

  var p = (((buf[offset]<<8)&0x3f00) | buf[offset+1]&0x00ff) + base; offset += 2;
  ret.name = getName(p, buf, 0);
  
  ret.type = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.class = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.ttl = ( ((buf[offset]<<24)&0xff000000) 
			 | ((buf[offset+1]<<16)&0xff0000) 
			 | ((buf[offset+2]<<8)&0xff00) 
			 | (buf[offset+3]&0xff) 
			); offset += 4;
  var rdLen = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;  
  if(offset + rdLen > limit) return ret;
  
  if(ret.type == 1) //IPv4
	ret.rdata = getIpv4Str(offset, buf, rdLen);
  else if(ret.type == 5) //CNAME
  	ret.rdata = getName(offset, buf);
  else if(ret.type == 28) //IPv6
	ret.rdata = getIpv6Str(offset, buf, rdLen);

  offset += rdLen;  
  return ret;
}

function getQueries(buf) {
  var question = [];
  while(offset < limit) {
	var slen = buf[offset]&0xff; offset++;
	if(slen == 0) break;
	var label = [];
	for(var i=offset; i<offset+slen;i++) {
	  label.push(buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : '.');
	}
	question.push(label.join("")); 
	offset += slen;
  }
  var ret = new Object();
  if(offset <= limit) {
	ret.qType = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
	ret.qClass = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;	
  }
  ret.qName = question.join(".");

  return ret;
}

function getName(pos, buf, depth) {
  var ret = [];
  if(depth > 10) {
	return "Name contains pointer that loops";
  }
  while((pos < limit)) {
	var slen = (buf[(pos)]&0xff); pos++;
	var label = [];
	if(slen == 0) {
	  break;  // stop processing after last label
	} else if ((slen&0xc0)!=0) { //referred label in compressed message
	  newPos = (((slen<<8)&0x3f00) | buf[pos]&0x00ff) + base;
	  if(newPos < limit) {
		var nDepth = depth + 1;
		ret.push(getName(newPos, buf, nDepth));		  
	  }
	  break;
	}
  	for(var i=pos; i<pos+slen && i<limit;i++) {
	  label.push(buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : '.');
	}
	ret.push(label.join("")); 
	pos += slen;
  }
  return ret.join(".");
}
  
function getIpv4Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<(pos+len) && i<limit;i++) {
	ret.push((buf[i]&0xff).toString());
  }
  return ret.join(".");  
}

function getIpv6Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<(pos+len) && i<limit;i+=2) {
	ret.push( pad((buf[i]&0xff).toString(16),2) + pad((buf[i+1]&0xff).toString(16),2));
  }
  return ret.join(":");  
}

function pad(num, size) {
  var s = ""+num;
  while (s.length < size) s = "0" + s;
  return s;
}

/* computes payload offset in buf 
   returns true if payload exists.
*/
function processHdr(buf, captureLen) {
  limit = captureLen + 16; //+pcap header len;
  
  if(limit < 58) //min len of IPv4 UDP
	return false;
  	  
  var nwHdrType = (((buf[28]<<8)&0xff00) | buf[29]&0x00ff);
  var nwHdrLen = 20;    //default IPv4 hdr, length 20 bytes
  var vlanHdrLen = 0;
  var trlProto = 17;	//transport layer proto default UDP
  var trlHdrLen = 8; 	//transport layer header length default: UDP header is 8 bytes

  if(nwHdrType == 0x86dd) { //IPv6
	nwHdrLen = 40;			//IPV6 network layer header is 40 bytes
	trlProto = buf[36]&0xff;
  } else if (nwHdrType == 0x800) {  //IPv4
	trlProto = buf[39]&0xff;
  } 
  
  if (nwHdrType == 8100) {//VLAN
	vlanHdrLen = 4;
  }
  
  if(trlProto == 6 && limit >= 65) {	//TCP
	trlHdrLen = (((buf[62]>>4)&0xf) * 4);
  }
  
  base = 16  		//tcpdump hdr: ts_sec, ts_usec, incl_len, orig_len
    + 14 			//link-layer header: srcMac 6, dstMac 6, nwHdrType 2 bytes
    + vlanHdrLen	//vlan labels
	+ nwHdrLen 		
    + trlHdrLen
  ;

  if(trlProto == 6 && limit > base)	
	base += 2; //skip payload length in case of TCP 
  
  offset = base;
  return (limit-base) > 0;
}

