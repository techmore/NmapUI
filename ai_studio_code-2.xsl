<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>
  
  <!-- Keys for grouping (Unchanged logic from your original) -->
  <xsl:key name="svcByProdVer" match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]" use="concat(@product,'|',@version)"/>
  <xsl:key name="svcByProdVerHostPort" match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]" use="concat(@product,'|',@version,'|', ancestor::host/address/@addr,'|', ../@protocol,'|',../@portid)"/>
  <xsl:key name="sshSvcs" match="nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']" use="1"/>

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Nmap Results | Pentest Factory</title>
        
        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif&amp;family=Inter:wght@400;500;600&amp;display=swap" rel="stylesheet" />
        
        <!-- Tailwind CDN (For development/standalone reports) -->
        <script src="https://cdn.tailwindcss.com"></script>
        
        <!-- DataTables CSS -->
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css" />
        
        <script>
          tailwind.config = {
            theme: {
              extend: {
                colors: {
                  olive: {
                    50: 'oklch(96% 0.015 110)',
                    100: 'oklch(91% 0.020 110)',
                    200: 'oklch(85% 0.028 110)',
                    300: 'oklch(75% 0.040 110)',
                    400: 'oklch(62% 0.055 110)',
                    500: 'oklch(50% 0.065 110)',
                    600: 'oklch(42% 0.055 110)',
                    700: 'oklch(35% 0.045 110)',
                    800: 'oklch(22% 0.025 110)',
                    900: 'oklch(22% 0.025 110)',
                    950: 'oklch(16% 0.015 110)',
                  }
                },
                fontFamily: {
                  display: ['Instrument Serif', 'serif'],
                  sans: ['Inter', 'system-ui', 'sans-serif'],
                }
              }
            }
          }
        </script>

        <style>
          body {
            background-color: oklch(91% 0.012 106.5);
            color: oklch(15.3% 0.006 107.1);
            -webkit-font-smoothing: antialiased;
          }
          h1, h2, h3 { font-family: 'Instrument Serif', serif; }
          
          /* Modern Table Styling */
          .dataTables_wrapper { padding: 20px 0; }
          table.dataTable {
            border-collapse: separate !important;
            border-spacing: 0 !important;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid oklch(85% 0.028 110);
          }
          table.dataTable thead th {
            background-color: oklch(22% 0.025 110);
            color: white;
            padding: 12px 15px;
            font-weight: 500;
            border: none;
          }
          table.dataTable tbody tr { background-color: white; }
          table.dataTable tbody tr:nth-child(even) { background-color: oklch(96% 0.015 110); }
          table.dataTable tbody tr:hover { background-color: oklch(85% 0.028 110) !important; }
          
          /* Pulsing Effect for Online Hosts */
          .card-pulsing {
            animation: pulse-border 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
            border: 2px solid oklch(22% 0.025 110) !important;
          }
          @keyframes pulse-border {
            0%, 100% { box-shadow: 0 0 0 4px oklch(62% 0.055 110 / 0.4); }
            50% { box-shadow: 0 0 0 10px oklch(62% 0.055 110 / 0.1); }
          }

          input {
            background-color: oklch(98% 0.008 110);
            border: 1px solid oklch(75% 0.040 110);
            border-radius: 9999px;
            padding: 8px 16px;
          }
        </style>
      </head>

      <body class="font-sans">
        <!-- Navigation -->
        <nav class="fixed top-0 w-full z-50 bg-olive-900 text-white py-4 px-8 flex justify-between items-center shadow-lg">
          <div class="text-2xl font-display">Pentest Factory <span class="text-olive-400 font-sans text-sm ml-2 tracking-widest uppercase">Nmap Report</span></div>
          <div class="hidden md:flex gap-6 text-sm font-medium">
            <a href="#scannedhosts" class="hover:text-olive-300 transition-colors">Hosts</a>
            <a href="#openservices" class="hover:text-olive-300 transition-colors">Services</a>
            <a href="#productversions" class="hover:text-olive-300 transition-colors">Products</a>
            <a href="#onlinehosts" class="hover:text-olive-300 transition-colors underline decoration-olive-400 underline-offset-4">Online Detail</a>
          </div>
        </nav>

        <main class="container mx-auto px-4 pt-32 pb-20">
          <!-- Hero Section -->
          <div class="bg-white rounded-[2rem] p-12 mb-12 border border-olive-200 shadow-sm relative overflow-hidden">
            <div class="relative z-10">
              <h1 class="text-6xl mb-4 text-olive-900">Nmap Port Scanning Results</h1>
              <p class="text-olive-600 text-xl max-w-2xl mb-8 leading-relaxed">
                Scan performed on <xsl:value-of select="/nmaprun/@startstr"/> using Nmap <xsl:value-of select="/nmaprun/@version"/>.
              </p>
              
              <div class="flex flex-wrap gap-4 mb-8">
                <div class="bg-olive-50 px-6 py-3 rounded-2xl border border-olive-100">
                  <span class="block text-xs uppercase text-olive-500 font-bold tracking-wider">Total Hosts</span>
                  <span class="text-2xl font-display text-olive-900"><xsl:value-of select="/nmaprun/runstats/hosts/@total"/></span>
                </div>
                <div class="bg-green-50 px-6 py-3 rounded-2xl border border-green-100">
                  <span class="block text-xs uppercase text-green-600 font-bold tracking-wider">Hosts Up</span>
                  <span class="text-2xl font-display text-green-900"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/></span>
                </div>
              </div>

              <!-- Keywords Control -->
              <div class="flex gap-2 items-center">
                <input type="text" id="keyword-input" placeholder="sha1, login, password..." class="w-64 focus:ring-2 ring-olive-400 outline-none" />
                <button onclick="highlight()" class="bg-olive-900 text-white px-6 py-2 rounded-full hover:bg-black transition-all font-medium">Highlight</button>
              </div>
            </div>
            <!-- Decorative background element -->
            <div class="absolute top-0 right-0 -mr-20 -mt-20 w-96 h-96 bg-olive-50 rounded-full blur-3xl opacity-50"></div>
          </div>

          <!-- Tables Sections -->
          <section id="scannedhosts" class="mb-20">
            <h2 class="text-4xl mb-6 text-olive-900">Scanned Hosts</h2>
            <div class="overflow-hidden">
              <table id="table-overview" class="w-full">
                <thead>
                  <tr>
                    <th>State</th>
                    <th>Address</th>
                    <th>Hostname</th>
                    <th>TCP</th>
                    <th>UDP</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host">
                    <tr>
                      <td class="px-4">
                        <span class="px-3 py-1 rounded-full text-xs font-bold uppercase">
                          <xsl:attribute name="class">
                            <xsl:choose>
                              <xsl:when test="status/@state='up'">bg-green-100 text-green-700 px-3 py-1 rounded-full text-xs font-bold uppercase</xsl:when>
                              <xsl:otherwise>bg-red-100 text-red-700 px-3 py-1 rounded-full text-xs font-bold uppercase</xsl:otherwise>
                            </xsl:choose>
                          </xsl:attribute>
                          <xsl:value-of select="status/@state"/>
                        </span>
                      </td>
                      <td class="font-medium px-4"><xsl:value-of select="address/@addr"/></td>
                      <td class="px-4"><xsl:value-of select="hostnames/hostname/@name"/></td>
                      <td class="px-4"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                      <td class="px-4"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <!-- Detail Cards for Online Hosts -->
          <section id="onlinehosts">
            <h2 class="text-4xl mb-8 text-olive-900">Host Detail Cards</h2>
            <div class="grid grid-cols-1 gap-8">
              <xsl:for-each select="/nmaprun/host[status/@state='up']">
                <div class="bg-white rounded-3xl p-8 border border-olive-200 transition-all hover:shadow-xl card-pulsing">
                  <div class="flex justify-between items-start mb-6">
                    <div>
                      <h3 class="text-3xl text-olive-900"><xsl:value-of select="address/@addr"/></h3>
                      <p class="text-olive-500 font-medium"><xsl:value-of select="hostnames/hostname/@name"/></p>
                    </div>
                    <div class="text-right">
                      <span class="bg-olive-900 text-white px-4 py-1 rounded-full text-xs uppercase tracking-tighter">Live Target</span>
                    </div>
                  </div>

                  <!-- Port List inside card -->
                  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <xsl:for-each select="ports/port[state/@state='open']">
                      <div class="bg-olive-50 p-4 rounded-2xl border border-olive-100">
                        <div class="flex items-center gap-3 mb-2">
                          <span class="bg-olive-200 text-olive-800 px-2 py-1 rounded-lg text-xs font-bold">
                            <xsl:value-of select="@portid"/>/<xsl:value-of select="@protocol"/>
                          </span>
                          <span class="text-sm font-semibold text-olive-900"><xsl:value-of select="service/@name"/></span>
                        </div>
                        <div class="text-xs text-olive-600 truncate">
                          <xsl:value-of select="service/@product"/> <xsl:value-of select="service/@version"/>
                        </div>
                      </div>
                    </xsl:for-each>
                  </div>
                </div>
              </xsl:for-each>
            </div>
          </section>
        </main>

        <footer class="bg-olive-950 text-olive-400 py-12 text-center text-sm">
          <p>© 2024 Pentest Factory GmbH | Powered by Nmap Bootstrap XSL 2.0</p>
        </footer>

        <!-- JS Scripts -->
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
        <script>
          $(document).ready(function() {
            $('#table-overview').DataTable({
              paging: true,
              searching: true,
              info: false,
              pageLength: 10
            });
          });

          function highlight() {
            const keywords = $('#keyword-input').val().split(',').map(k => k.trim());
            if(!keywords[0]) return;
            
            $('td, .text-xs').each(function() {
              let html = $(this).html();
              keywords.forEach(word => {
                if(word.length > 2) {
                  const reg = new RegExp(`(${word})`, 'gi');
                  html = html.replace(reg, '<span class="bg-yellow-200 text-red-600 font-bold">$1</span>');
                }
              });
              $(this).html(html);
            });
          }
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>