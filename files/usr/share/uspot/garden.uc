// SPDX-License-Identifier: GPL-2.0-only
// garden.uc - Walled garden management for uspot
//
// Manages static and dynamic walled garden pass-throughs using nftables sets.
// Unauthenticated clients can reach garden destinations without logging in.

'use strict';

let fs = require('fs');
import { ulog_open, ulog, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG, ERR, WARN, INFO } from 'log';

/**
 * Resolve a hostname to IPv4 addresses using system resolver.
 *
 * @param {string} host - hostname to resolve
 * @returns {array} list of IPv4 address strings, or empty array on failure
 */
function resolve_host(host) {
	let addrs = [];

	// Use getaddrinfo via nslookup (available on OpenWrt base)
	let stdout = fs.popen(`nslookup ${host} 2>/dev/null`);
	if (!stdout)
		return addrs;

	let output = stdout.read('all');
	stdout.close();

	if (!output)
		return addrs;

	// Parse nslookup output: skip the first "Address:" line (DNS server)
	// and collect subsequent "Address:" lines (resolved IPs)
	let seen_server = false;
	for (let line in split(output, '\n')) {
		let m = match(line, /^Address\s*\d*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
		if (m) {
			if (!seen_server) {
				seen_server = true;
				continue;
			}
			push(addrs, m[1]);
		}
	}

	return addrs;
}

/**
 * Build nftables set elements from garden configuration.
 *
 * @param {object} config - garden config with garden_host and garden_network lists
 * @returns {object} { elements: string[], resolved: object } elements for nft set, resolved host map
 */
function build_elements(config) {
	let elements = [];
	let resolved = {};

	// Add static networks/IPs directly
	if (config.garden_network) {
		let networks = (type(config.garden_network) == 'array') ? config.garden_network : [ config.garden_network ];
		for (let net in networks) {
			if (net && length(net))
				push(elements, net);
		}
	}

	// Resolve hostnames and add their IPs
	if (config.garden_host) {
		let hosts = (type(config.garden_host) == 'array') ? config.garden_host : [ config.garden_host ];
		for (let host in hosts) {
			if (!host || !length(host))
				continue;

			let addrs = resolve_host(host);
			if (length(addrs)) {
				resolved[host] = addrs;
				for (let addr in addrs)
					push(elements, addr);
			}
			else {
				WARN('garden: failed to resolve host: ' + host);
			}
		}
	}

	return { elements, resolved };
}

/**
 * Apply garden elements to an nftables set.
 * Flushes existing elements and adds new ones.
 *
 * @param {string} setname - nftables set name (e.g. "uspot_garden_hotspot1")
 * @param {array} elements - list of IP/network strings to add
 * @returns {number} 0 on success, non-zero on failure
 */
function apply_garden_set(setname, elements) {
	// Flush existing elements
	system(`nft flush set inet fw4 ${setname} 2>/dev/null`);

	if (!length(elements))
		return 0;

	// Add all elements in a single command
	let elem_str = join(', ', elements);
	let ret = system(`nft add element inet fw4 ${setname} { ${elem_str} }`);

	if (ret)
		ERR('garden: failed to add elements to set ' + setname);

	return ret;
}

/**
 * Create the nftables garden set if it doesn't exist.
 *
 * @param {string} setname - nftables set name
 * @returns {number} 0 on success
 */
function create_garden_set(setname) {
	return system(`nft add set inet fw4 ${setname} '{ type ipv4_addr; flags interval; }' 2>/dev/null`);
}

/**
 * Destroy the nftables garden set.
 *
 * @param {string} setname - nftables set name
 */
function destroy_garden_set(setname) {
	system(`nft flush set inet fw4 ${setname} 2>/dev/null`);
	system(`nft delete set inet fw4 ${setname} 2>/dev/null`);
}

/**
 * Add a garden forwarding rule for a device+set.
 * This rule allows traffic from the captive interface to garden destinations.
 *
 * @param {string} device - network device (e.g. "br-guest")
 * @param {string} setname - garden nftables set name
 * @param {string} chain - fw4 chain to insert rule into
 * @returns {number} 0 on success
 */
function add_garden_rule(device, setname, chain) {
	// Insert at the beginning of the chain so it's checked before MAC auth
	return system(`nft insert rule inet fw4 ${chain} iifname ${device} ip daddr @${setname} accept comment "uspot-garden-${setname}" 2>/dev/null`);
}

/**
 * Remove garden forwarding rules for a set.
 *
 * @param {string} setname - garden nftables set name
 */
function remove_garden_rules(setname) {
	// Find and delete rules with our comment
	let stdout = fs.popen(`nft -a list chain inet fw4 forward 2>/dev/null`);
	if (!stdout)
		return;

	let output = stdout.read('all');
	stdout.close();

	if (!output)
		return;

	for (let line in split(output, '\n')) {
		let m = match(line, /uspot-garden-${setname}.*# handle (\d+)/);
		if (m)
			system(`nft delete rule inet fw4 forward handle ${m[1]}`);
	}
}

/**
 * Create nftables named counters for garden traffic accounting.
 *
 * @param {string} spotname - uspot section name
 */
function create_garden_counters(spotname) {
	system(`nft add counter inet fw4 garden_in_${spotname} 2>/dev/null`);
	system(`nft add counter inet fw4 garden_out_${spotname} 2>/dev/null`);
}

/**
 * Destroy nftables garden counters.
 *
 * @param {string} spotname - uspot section name
 */
function destroy_garden_counters(spotname) {
	system(`nft delete counter inet fw4 garden_in_${spotname} 2>/dev/null`);
	system(`nft delete counter inet fw4 garden_out_${spotname} 2>/dev/null`);
}

/**
 * Add nftables counting rules for garden traffic.
 * These rules count traffic matching the garden set without affecting forwarding.
 *
 * @param {string} device - network device name
 * @param {string} setname - garden nftables set name
 * @param {string} spotname - uspot section name (for counter names)
 */
function add_garden_counter_rules(device, setname, spotname) {
	// Count outbound (client → garden): src is captive iface, dst in garden set
	system(`nft insert rule inet fw4 forward iifname ${device} ip daddr @${setname} counter name garden_out_${spotname} comment "uspot-garden-count-${spotname}" 2>/dev/null`);
	// Count inbound (garden → client): dst is captive iface, src in garden set
	system(`nft insert rule inet fw4 forward oifname ${device} ip saddr @${setname} counter name garden_in_${spotname} comment "uspot-garden-count-${spotname}" 2>/dev/null`);
}

/**
 * Remove garden counter rules.
 *
 * @param {string} spotname - uspot section name
 */
function remove_garden_counter_rules(spotname) {
	let stdout = fs.popen('nft -a list chain inet fw4 forward 2>/dev/null');
	if (!stdout)
		return;

	let output = stdout.read('all');
	stdout.close();

	if (!output)
		return;

	for (let line in split(output, '\n')) {
		let m = match(line, /uspot-garden-count-${spotname}.*# handle (\d+)/);
		if (m)
			system(`nft delete rule inet fw4 forward handle ${m[1]}`);
	}
}

/**
 * Read garden counter values via nftables JSON output.
 *
 * @param {string} spotname - uspot section name
 * @returns {object} { bytes_in, bytes_out, packets_in, packets_out } or null
 */
function read_garden_counters(spotname) {
	let result = { bytes_in: 0, bytes_out: 0, packets_in: 0, packets_out: 0 };

	// Read inbound counter (garden → client = download)
	let stdout = fs.popen(`nft -j list counter inet fw4 garden_in_${spotname} 2>/dev/null`);
	if (stdout) {
		let data = stdout.read('all');
		stdout.close();
		try {
			let parsed = json(data);
			let counter = parsed?.nftables?.[1]?.counter;
			if (counter) {
				result.bytes_in = counter.bytes || 0;
				result.packets_in = counter.packets || 0;
			}
		} catch(e) {}
	}

	// Read outbound counter (client → garden = upload)
	stdout = fs.popen(`nft -j list counter inet fw4 garden_out_${spotname} 2>/dev/null`);
	if (stdout) {
		let data = stdout.read('all');
		stdout.close();
		try {
			let parsed = json(data);
			let counter = parsed?.nftables?.[1]?.counter;
			if (counter) {
				result.bytes_out = counter.bytes || 0;
				result.packets_out = counter.packets || 0;
			}
		} catch(e) {}
	}

	return result;
}

return {
	resolve_host,
	build_elements,
	apply_garden_set,
	create_garden_set,
	destroy_garden_set,
	add_garden_rule,
	remove_garden_rules,
	create_garden_counters,
	destroy_garden_counters,
	add_garden_counter_rules,
	remove_garden_counter_rules,
	read_garden_counters,
};
