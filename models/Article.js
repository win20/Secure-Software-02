/* eslint-disable func-names */
/* eslint-disable max-len */
const mongoose = require('mongoose');
const marked = require('marked');
const slugify = require('slugify');

// Functions needed to purify and secure markdown
const createDomPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const dompurify = createDomPurify(new JSDOM().window);

// Create mongoDB schema for article
const articleSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
    },
    markdown: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    slug: {
        type: String,
        required: true,
        unique: true,
    },
    sanitizedHTML: {
        type: String,
        required: true,
    },
});

// Runs before validating any article,
// a slug (meaningful url instead of id) is created from the article title,
// the markdown is sanitized to avoid cross-site scripting and parsed so it can be displayed with the correct formatting in /show
articleSchema.pre('validate', function (next) {
    if (this.title) {
        this.slug = slugify(this.title, { lower: true, strict: true });
    }

    if (this.markdown) {
        this.sanitizedHTML = dompurify.sanitize(marked.parse(this.markdown));
    }

    next();
});

module.exports = mongoose.model('Article', articleSchema);
