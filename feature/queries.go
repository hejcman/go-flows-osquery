package osquery_feature

// Used as a single entry point for executing SQL requests on the OSQuery client.
// Parses the response and handles errors.
func (q *osqueryFeature) execQuery(sql string) ([]map[string]string, error) {
	response, err := q.client.Query(sql)
	if err != nil {
		return nil, err
	} else {
		return response.Response, nil
	}
}

func (q *osqueryFeature) getOsInfo() (err error) {
	sql := "SELECT * FROM os_version LIMIT 1;\n"
	tmp, err := q.execQuery(sql)
	if err != nil {
		return
	}

	// Set the whole os_version table to osInfo map, so that all info is available.
	// os_version table schema: https://www.osquery.io/schema/5.1.0/#os_version
	q.osInfo = tmp[0]
	return
}
