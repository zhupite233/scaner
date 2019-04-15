function makeCharts(div_id, categories_content, series_content_data) {
	$("#" + div_id).highcharts({
		chart: {
			type: "column",
			margin: [30, 10, 60, 50]
		},
		title: {
			text: ""
		},
		xAxis: {
			categories: categories_content,
			labels: {
				rotation: -45,
				align: "right",
				style: {
					fontSize: "8px",
					fontFamily: "Verdana, sans-serif"
				}
			}
		},
		yAxis: {
			min: 0,
			lineWidth: 1,
			maxPadding: .05,
			title: {
				align: "high",
				offset: 0,
				text: "婕忔礊鏁伴噺",
				rotation: 0,
				y: -15
			}
		},
		legend: {
			enabled: !1
		},
		tooltip: {
			pointFormat: "婕忔礊鎬绘暟: <b>{point.y:.1f} 涓�/b>"
		},
		series: [{
			name: "婕忔礊鏁�",
			data: series_content_data,
			dataLabels: {
				enabled: !0,
				rotation: 0,
				color: "#000000",
				align: "center",
				x: 3,
				y: 10,
				style: {
					fontSize: "5px",
					fontFamily: "Verdana, sans-serif",
					textShadow: "0 0 0 black"
				}
			}
		}]
	});
}