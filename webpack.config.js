const path = require('path');
const webpack = require('webpack');
const TerserPlugin = require('terser-webpack-plugin');


const environment = {
  dev: {
    output: {
      path: path.resolve(__dirname, '../../dist/dev-boxState'), // Output directory
      filename: 'boxState.js' // Output filename
    },
    mode: 'development',
    devtool: 'source-map',
    sourceMap: true,
  },
  prod: {
    output: {
      path: path.resolve(__dirname, '../../dist/boxState'), // Output directory
      filename: 'boxState.js' // Output filename
    },
    mode: 'production',
    devtool: false,
    sourceMap: false,
  }
}

const useEnv = environment.dev;

module.exports = {
  entry: './index.js', // Entry point
  output: useEnv.output,
  mode: useEnv.mode, // or 'development' for non-minified output
  target: 'web', // ensure code is targeted for the browser
  devtool: useEnv.devtool,
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          // Terser options
          compress: false, // Disable compression
          mangle: false,   // Disable mangling
          keep_classnames: true, // Preserve class names
          keep_fnames: false,     // Preserve function names
          sourceMap: useEnv.sourceMap,
          output: {
            comments: /@license|@Hello|@Notes/, //'license', // Retain some comments based on pragma
          },
        }
      }),
    ],
  },
  plugins: [
    new webpack.BannerPlugin({
      banner: `
      ============================================================================
      ===============**********************************************===============
          @Hello

          For custom solutions and inquiries, please contact me 
          at ipongrani@protonmail.com. 

      ===============______________________________________________===============
      ============================================================================
      `
    })
  ],
  module: {
    rules: [
      {
        test: /\.js$/, // Apply the following loaders to .js files
        exclude: /node_modules/, // Exclude node_modules directory
        use: {
          loader: 'babel-loader', // Use babel-loader for transpiling
          options: {
            presets: ['@babel/preset-env'] // Use @babel/preset-env for modern JavaScript
          }
        }
      }
    ]
  }
};