var pcap = require('pcap')
var os = require('os')
var dns = require('dns')
var pg = require('pg')
var moment = require('moment')
var url = require('url')
var wget = require('wget-improved')
var http = require('http')

moment().format('DD-MM-YY')
var datetoday = moment(Date.now()).format('DDMMYY')

var conString = "postgres://siteswatch:mylog@localhost/pcaplog";
var db = new pg.Client(conString);

db.connect(function(err) {
	if(err) {
		return console.error('could not connect to postgres', err);
	}
})

db.query("CREATE TABLE IF NOT EXISTS rlog" + datetoday + " (start boolean, src inet, dst inet, time time)", function(err, result) {
	if(err)
		console.log("rlog Table creation error!");
})

var tcp_tracker = new pcap.TCPTracker()
var pcap_session = pcap.createSession("", "")

tcp_tracker.on('session', function (session) {
	var src = session.src_name.split(":")[0]
	var dst = session.dst_name.split(":")[0]
	console.log("Start of session between " + src + " and " + dst);
	db.query("INSERT INTO rlog" + datetoday + " VALUES (TRUE, \'" + src + "\', \'" + dst + "\', LOCALTIME(0))", function(err, result) {
		if(err)
			console.log("rlog Table (start session) insertion error!");
	});
  
	session.on('end', function (session) {
		var src = session.src_name.split(":")[0]
		var dst = session.dst_name.split(":")[0]
		console.log("End of TCP session between " + src + " and " + dst);
		db.query("INSERT INTO rlog" + datetoday + " VALUES (FALSE, \'" + src + "\', \'" + dst + "\', LOCALTIME(0))", function(err, result) {
			if(err)
				console.log("rlog table (end session) insertion error!");
		});
	});
});

pcap_session.on('packet', function (raw_packet) {
	var packet = pcap.decode.packet(raw_packet);
	tcp_tracker.track_packet(packet);
});