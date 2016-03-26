var pcap = require('pcap')
var os = require('os')
var dns = require('dns')
var pg = require('pg')
var moment = require('moment')
var url = require('url')
var wget = require('wget-improved')
var request = require('request')
var express = require('express')
var path = require('path')
var fs = require('fs')
var d3 = require('d3')
var app = express()
var lookup = require('node-rest-client').Client
var iplookup = new lookup()
var iplookupapi = "http://www.linkexpander.com/?url="
var myip = ''
var site = ''

dns.lookup(os.hostname(), function (err, address, family) {
	myip = address
	console.log("System IP address: " + address)
})

app.set('views', '.')
app.set('view engine','ejs')

app.get('/',function(req,res) {
	fs.writeFile("stats.tsv", "", function(err) {
	    if(err) {
	        return console.log(err);
	    }
	})
	var result = db.query("SELECT * FROM tlog" + datetoday)
	result.on('row', function(row) {
		console.log('user "%s" is %s years old', row.url, row.time)
		fs.appendFile("stats.tsv", row.url + " " + row.time + "\n", function(err) {
		    if(err) {
		        return console.log(err);
		    }
		})
	    })
		res.render('stats')
})

moment().format('DD-MM-YY')
var datetoday = moment(Date.now()).format('DDMMYY')

var conString = "postgres://siteswatch:mylog@localhost/pcaplog"
var db = new pg.Client(conString)

db.connect(function(err) {
	if(err) {
		return console.error('could not connect to postgres', err)
	}
})

db.query("CREATE TABLE IF NOT EXISTS rlog" + datetoday + " (start boolean, dst inet, startdate varchar)", function(err, result) {
	if(err)
		console.log("😕 rlog table")
})

db.query("CREATE TABLE IF NOT EXISTS tlog" + datetoday + " (url varchar, time varchar)", function(err, result) {
	if(err) {
		console.log("😟 tlog table")
		console.log(err)
	}
})

var tcp_tracker = new pcap.TCPTracker()
var pcap_session = pcap.createSession("", "")

tcp_tracker.on('session', function (session) {
	var src = session.src_name.split(":")[0]
	var dst = session.dst_name.split(":")[0]
	var serv = src === myip ? dst : src
	if(serv !== "192.186.215.100") { //ip of longurl api
		console.log("Start of session between " + src + " and " + dst)
		db.query("INSERT INTO rlog" + datetoday + " VALUES (TRUE, \'" + serv + "\', " + moment() +")", function(err, result) {
			if(err) {
				console.log("😫 rlog insertion")
				console.log(err)
			}
		})
	}
  
	session.on('end', function (session) {
		var src = session.src_name.split(":")[0]
		var dst = session.dst_name.split(":")[0]
		var serv = src === myip ? dst : src
		if(serv !== "192.186.215.100") { //ip of longurl api
			var startdate = ''
			var start = db.query("DELETE FROM rlog" + datetoday + " WHERE ctid IN (SELECT ctid FROM rlog" + datetoday + " ORDER BY startdate LIMIT 1) RETURNING *", function(err, result) {
				if(err) {
					console.log("😞 rlog deletion")
					console.log(err)
				}
			})
			start.on('row', function(row) {
				startdate = row.startdate
			})
			var totalTime = moment.duration(moment().diff(startdate)).asSeconds()
			iplookup.get(iplookupapi + serv, function(data, response) {
				site = data.toString('utf8')
				console.log("site: " + site)
			})
			if(site) {
				totalTime = totalTime === 0 ? 1 : totalTime 
				db.query("INSERT INTO tlog" + datetoday + " VALUES (\'" + site + "\', \'" + totalTime + "\')", function(err, result) {
					if(err) {
						console.log("😔 tlog insertion")
						console.log(err)
					}
				})
			}
			console.log("End of TCP session between " + src + " and " + dst)
		}
	})
})

pcap_session.on('packet', function (raw_packet) {
	var packet = pcap.decode.packet(raw_packet)
	tcp_tracker.track_packet(packet)
})

app.listen(3000);
