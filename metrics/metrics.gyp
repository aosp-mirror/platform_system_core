{
  'target_defaults': {
      'dependencies': [
        '../libchromeos/libchromeos-<(libbase_ver).gyp:libchromeos-<(libbase_ver)',
      ],
      'variables': {
        'deps': [
          'dbus-1',
          'dbus-glib-1',
          'glib-2.0',
          'gobject-2.0',
          'gthread-2.0',
          'libchrome-<(libbase_ver)',
        ]
      },
      'cflags_cc': [
        '-fno-exceptions',
      ],
  },
  'targets': [
    {
      'target_name': 'metrics',
      'type': 'static_library',
      'sources': [
        'c_metrics_library.cc',
        'metrics_library.cc',
        'timer.cc',
      ],
    },
    {
      'target_name': 'libmetrics',
      'type': 'shared_library',
      'sources': [
        'c_metrics_library.cc',
        'metrics_library.cc',
        'timer.cc',
      ],
    },
    {
      'target_name': 'libmetrics_daemon',
      'type': 'static_library',
      'dependencies': ['libmetrics'],
      'link_settings': {
        'libraries': [
          '-lrootdev',
          '-lgflags',
        ],
      },
      'sources': [
        'counter.cc',
        'metrics_daemon.cc',
        'metrics_daemon_main.cc',
      ]
    },
    {
      'target_name': 'metrics_client',
      'type': 'executable',
      'dependencies': ['libmetrics'],
      'sources': [
        'metrics_client.cc',
      ]
    },
  ],
  'conditions': [
    ['USE_passive_metrics == 1', {
      'targets': [
        {
          'target_name': 'metrics_daemon',
          'type': 'executable',
          'dependencies': ['libmetrics_daemon'],
        },
      ],
    }],
    ['USE_test == 1', {
      'targets': [
        {
          'target_name': 'metrics_library_test',
          'type': 'executable',
          'dependencies': ['libmetrics'],
          'includes': ['../common-mk/common_test.gypi'],
          'sources': [
            'metrics_library_test.cc',
          ]
        },
        {
          'target_name': 'counter_test',
          'type': 'executable',
          'includes': ['../common-mk/common_test.gypi'],
          'sources': [
            'counter.cc',
            'counter_test.cc',
          ]
        },
        {
          'target_name': 'timer_test',
          'type': 'executable',
          'includes': ['../common-mk/common_test.gypi'],
          'sources': [
            'timer.cc',
            'timer_test.cc',
          ]
        },
      ],
    }],
    ['USE_passive_metrics == 1 and USE_test == 1', {
      'targets': [
        {
          'target_name': 'metrics_daemon_test',
          'type': 'executable',
          'dependencies': [
            'libmetrics_daemon',
          ],
          'includes': ['../common-mk/common_test.gypi'],
          'sources': [
            'metrics_daemon_test.cc',
          ]
        },
      ],
    }],
  ],
}
